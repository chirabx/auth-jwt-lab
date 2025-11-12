// server/app.js
import "dotenv/config";
import express from "express";
import session from "express-session";
import cors from "cors";
import axios from "axios";
import cookieParser from "cookie-parser";
import crypto from "node:crypto";
import { SignJWT, jwtVerify } from "jose";

const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));
app.use(cookieParser());
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" }
    })
);

// —— PKCE 工具 ——
const b64url = (buf) => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const genState = () => b64url(crypto.randomBytes(16));
const genVerifier = () => b64url(crypto.randomBytes(32));
const sha256 = (str) => crypto.createHash("sha256").update(str).digest();

// 触发登录：跳转 GitHub /authorize
app.get("/auth/github", (req, res) => {
    const state = genState();
    const code_verifier = genVerifier();
    const code_challenge = b64url(sha256(code_verifier));
    req.session.oauth = { state, code_verifier };

    const params = new URLSearchParams({
        client_id: process.env.GITHUB_CLIENT_ID,
        redirect_uri: process.env.GITHUB_REDIRECT_URI,
        scope: "read:user user:email",
        state,
        code_challenge,
        code_challenge_method: "S256",
        allow_signup: "true"
    });
    res.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
});

// 回调：code→access_token→获取用户→签发自家 JWT 到 HttpOnly Cookie
app.get("/auth/callback", async (req, res, next) => {
    try {
        const { code, state } = req.query;
        const { oauth } = req.session || {};
        if (!oauth || state !== oauth.state) return res.status(400).send("state mismatch");

        const tokenRes = await axios.post(
            "https://github.com/login/oauth/access_token",
            {
                client_id: process.env.GITHUB_CLIENT_ID,
                client_secret: process.env.GITHUB_CLIENT_SECRET,
                code,
                redirect_uri: process.env.GITHUB_REDIRECT_URI,
                grant_type: "authorization_code",
                code_verifier: oauth.code_verifier
            },
            { headers: { Accept: "application/json" } }
        );
        const ghAccessToken = tokenRes.data.access_token;
        if (!ghAccessToken) return res.status(401).send("no access_token");

        const me = await axios.get("https://api.github.com/user", {
            headers: { Authorization: `Bearer ${ghAccessToken}`, "User-Agent": "auth-jwt-lab" }
        });
        let email = null;
        try {
            const emails = await axios.get("https://api.github.com/user/emails", {
                headers: { Authorization: `Bearer ${ghAccessToken}`, "User-Agent": "auth-jwt-lab" }
            });
            email = (emails.data || []).find((e) => e.primary)?.email || null;
        } catch { }

        const secret = new TextEncoder().encode(process.env.JWT_SECRET);
        const claims = {
            sub: String(me.data.id),
            login: me.data.login,
            name: me.data.name,
            email,
            provider: "github",
            scope: "read:orders"
        };
        const jwt = await new SignJWT(claims)
            .setProtectedHeader({ alg: "HS256" })
            .setIssuer(process.env.JWT_ISSUER)
            .setAudience(process.env.JWT_AUDIENCE)
            .setExpirationTime("15m")
            .sign(secret);

        res.cookie("app_token", jwt, {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production",
            maxAge: 15 * 60 * 1000
        });
        req.session.user = { login: me.data.login, name: me.data.name };
        res.redirect(process.env.FRONTEND_URL);
    } catch (e) {
        next(e);
    }
});

// JWT 鉴权中间件（Cookie 优先）
async function auth(req, res, next) {
    try {
        const token = req.cookies?.app_token || (req.headers.authorization || "").replace(/^Bearer\s+/, "");
        if (!token) return res.status(401).json({ error: "missing_token" });
        const secret = new TextEncoder().encode(process.env.JWT_SECRET);
        const { payload } = await jwtVerify(token, secret, {
            issuer: process.env.JWT_ISSUER,
            audience: process.env.JWT_AUDIENCE,
            algorithms: ["HS256"]
        });
        req.user = payload;
        next();
    } catch (e) {
        res.status(401).json({ error: "invalid_token", detail: e.message });
    }
}

// 受保护 API
app.get("/api/me", auth, (req, res) => res.json({ user: req.user }));
app.get("/api/orders", auth, (req, res) => res.json([{ id: 1, owner: req.user.sub, by: req.user.login }]));

app.post("/auth/logout", (req, res) => {
    res.clearCookie("app_token", { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" });
    req.session.destroy(() => res.json({ ok: true }));
});

app.listen(3002, () => console.log("Server at http://localhost:3002"));