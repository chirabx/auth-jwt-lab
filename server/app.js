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
        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: false
        }
    })
);

// —— 安全配置 ——
const ACCESS_TOKEN_EXPIRY = "15m"; // Access Token 15分钟
const REFRESH_TOKEN_EXPIRY = "7d"; // Refresh Token 7天

// —— Token 黑名单（生产环境应使用 Redis）——
const tokenBlacklist = new Set();
const refreshTokenBlacklist = new Set();

// 定期清理过期 token（简化版，生产环境应基于过期时间）
setInterval(() => {
    // 这里可以添加基于时间的清理逻辑
    // 实际生产环境应使用 Redis TTL 自动过期
}, 60 * 60 * 1000); // 每小时清理一次

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
        const refreshSecret = new TextEncoder().encode(process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET + "_refresh");

        // 用户信息
        const userClaims = {
            sub: String(me.data.id),
            login: me.data.login,
            name: me.data.name,
            email,
            provider: "github",
            scope: "read:orders"
        };

        // 签发 Access Token（15分钟）
        const accessToken = await new SignJWT(userClaims)
            .setProtectedHeader({ alg: "HS256" })
            .setIssuer(process.env.JWT_ISSUER)
            .setAudience(process.env.JWT_AUDIENCE)
            .setExpirationTime(ACCESS_TOKEN_EXPIRY)
            .setIssuedAt()
            .sign(secret);

        // 签发 Refresh Token（7天，包含基本用户信息用于刷新时重建 Access Token）
        const refreshTokenId = b64url(crypto.randomBytes(32)); // 唯一标识符
        const refreshToken = await new SignJWT({
            sub: String(me.data.id),
            jti: refreshTokenId, // JWT ID，用于轮换和撤销
            type: "refresh",
            login: me.data.login,
            name: me.data.name,
            email,
            provider: "github"
        })
            .setProtectedHeader({ alg: "HS256" })
            .setIssuer(process.env.JWT_ISSUER)
            .setAudience(process.env.JWT_AUDIENCE + "_refresh")
            .setExpirationTime(REFRESH_TOKEN_EXPIRY)
            .setIssuedAt()
            .sign(refreshSecret);

        // 设置 Cookie：HttpOnly, Secure, SameSite
        const cookieOptions = {
            httpOnly: true,
            secure: false,
            sameSite: "lax",
            path: "/"
        };

        // Access Token Cookie（15分钟）
        res.cookie("app_token", accessToken, {
            ...cookieOptions,
            maxAge: 15 * 60 * 1000 // 15分钟
        });

        // Refresh Token Cookie（7天）
        res.cookie("refresh_token", refreshToken, {
            ...cookieOptions,
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7天
        });

        // 存储 refresh token ID 到 session（用于轮换时撤销旧 token）
        req.session.user = {
            login: me.data.login,
            name: me.data.name,
            refreshTokenId
        };

        res.redirect(process.env.FRONTEND_URL);
    } catch (e) {
        next(e);
    }
});

// JWT 鉴权中间件（Cookie 优先，检查黑名单）
async function auth(req, res, next) {
    try {
        const token = req.cookies?.app_token || (req.headers.authorization || "").replace(/^Bearer\s+/, "");
        if (!token) return res.status(401).json({ error: "missing_token" });

        // 检查黑名单
        if (tokenBlacklist.has(token)) {
            return res.status(401).json({ error: "token_revoked" });
        }

        const secret = new TextEncoder().encode(process.env.JWT_SECRET);
        const { payload } = await jwtVerify(token, secret, {
            issuer: process.env.JWT_ISSUER,
            audience: process.env.JWT_AUDIENCE,
            algorithms: ["HS256"]
        });

        // 将 token 存储到请求对象，用于登出时加入黑名单
        req.token = token;
        req.user = payload;
        next();
    } catch (e) {
        // Token 过期时，尝试自动刷新
        if (e.code === "ERR_JWT_EXPIRED") {
            return res.status(401).json({ error: "token_expired", canRefresh: true });
        }
        res.status(401).json({ error: "invalid_token", detail: e.message });
    }
}

// 受保护 API
app.get("/api/me", auth, (req, res) => {
    const response = { user: req.user };
    // 显示 token 信息（用于调试）
    const token = req.cookies?.app_token || (req.headers.authorization || "").replace(/^Bearer\s+/, "");
    response.token = token;
    // 解码 token（不验证，仅用于查看）
    if (token) {
        try {
            const parts = token.split('.');
            if (parts.length === 3) {
                const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
                response.tokenPayload = payload;
            }
        } catch (e) {
            response.tokenDecodeError = e.message;
        }
    }
    res.json(response);
});
app.get("/api/orders", auth, (req, res) => res.json([{ id: 1, owner: req.user.sub, by: req.user.login }]));

// Refresh Token 接口（轮换机制）
app.post("/auth/refresh", async (req, res) => {
    try {
        const refreshToken = req.cookies?.refresh_token;
        if (!refreshToken) {
            return res.status(401).json({ error: "missing_refresh_token" });
        }

        // 检查刷新 token 黑名单
        if (refreshTokenBlacklist.has(refreshToken)) {
            return res.status(401).json({ error: "refresh_token_revoked" });
        }

        const refreshSecret = new TextEncoder().encode(process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET + "_refresh");
        const { payload } = await jwtVerify(refreshToken, refreshSecret, {
            issuer: process.env.JWT_ISSUER,
            audience: process.env.JWT_AUDIENCE + "_refresh",
            algorithms: ["HS256"]
        });

        if (payload.type !== "refresh") {
            return res.status(401).json({ error: "invalid_token_type" });
        }

        // 将旧的 refresh token 加入黑名单（轮换）
        refreshTokenBlacklist.add(refreshToken);

        const secret = new TextEncoder().encode(process.env.JWT_SECRET);

        // 生成新的 refresh token ID
        const newRefreshTokenId = b64url(crypto.randomBytes(32));

        // 从 refresh token 中获取用户信息
        const userClaims = {
            sub: payload.sub,
            login: payload.login,
            name: payload.name,
            email: payload.email,
            provider: payload.provider || "github",
            scope: "read:orders"
        };

        // 签发新的 Access Token
        const newAccessToken = await new SignJWT(userClaims)
            .setProtectedHeader({ alg: "HS256" })
            .setIssuer(process.env.JWT_ISSUER)
            .setAudience(process.env.JWT_AUDIENCE)
            .setExpirationTime(ACCESS_TOKEN_EXPIRY)
            .setIssuedAt()
            .sign(secret);

        // 签发新的 Refresh Token（轮换，包含用户信息）
        const newRefreshToken = await new SignJWT({
            sub: payload.sub,
            jti: newRefreshTokenId,
            type: "refresh",
            login: payload.login,
            name: payload.name,
            email: payload.email,
            provider: payload.provider || "github"
        })
            .setProtectedHeader({ alg: "HS256" })
            .setIssuer(process.env.JWT_ISSUER)
            .setAudience(process.env.JWT_AUDIENCE + "_refresh")
            .setExpirationTime(REFRESH_TOKEN_EXPIRY)
            .setIssuedAt()
            .sign(refreshSecret);

        const cookieOptions = {
            httpOnly: true,
            secure: false,
            sameSite: "lax",
            path: "/"
        };

        // 设置新的 tokens
        res.cookie("app_token", newAccessToken, {
            ...cookieOptions,
            maxAge: 15 * 60 * 1000
        });

        res.cookie("refresh_token", newRefreshToken, {
            ...cookieOptions,
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.json({ ok: true, message: "tokens_refreshed" });
    } catch (e) {
        if (e.code === "ERR_JWT_EXPIRED") {
            return res.status(401).json({ error: "refresh_token_expired" });
        }
        res.status(401).json({ error: "invalid_refresh_token", detail: e.message });
    }
});

// 登出接口（将 token 加入黑名单）
app.post("/auth/logout", auth, (req, res) => {
    const accessToken = req.token;
    const refreshToken = req.cookies?.refresh_token;

    // 将 tokens 加入黑名单
    if (accessToken) {
        tokenBlacklist.add(accessToken);
    }
    if (refreshToken) {
        refreshTokenBlacklist.add(refreshToken);
    }

    // 清除 cookies
    const cookieOptions = {
        httpOnly: true,
        secure: false,
        sameSite: "lax",
        path: "/"
    };

    res.clearCookie("app_token", cookieOptions);
    res.clearCookie("refresh_token", cookieOptions);

    req.session.destroy(() => res.json({ ok: true, message: "logged_out" }));
});

app.listen(3002, () => console.log("Server at http://localhost:3002"));