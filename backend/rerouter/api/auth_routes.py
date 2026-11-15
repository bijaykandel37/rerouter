from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from ..core import Platform
from .deps import COOKIE, audit, current_user, platform, token_from

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class PasswordIn(BaseModel):
    old: str
    new: str = Field(min_length=10, max_length=256)


@router.post("/login")
async def login(body: LoginIn, request: Request, response: Response,
                p: Platform = Depends(platform)):
    client = request.client.host if request.client else "?"
    token = await p.auth.login(body.username, body.password, client)
    if token is None:
        await audit(p, body.username, "login", {"client": client}, ok=False)
        raise HTTPException(401, "invalid credentials or too many attempts")
    await audit(p, body.username, "login", {"client": client})
    response.set_cookie(COOKIE, token, httponly=True, samesite="strict",
                        secure=p.cfg.cookie_secure, max_age=p.auth.ttl, path="/")
    return {"username": body.username, "token": token}


@router.post("/logout")
async def logout(request: Request, response: Response, p: Platform = Depends(platform)):
    token = token_from(request)
    if token:
        await p.auth.logout(token)
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
async def me(user: str = Depends(current_user)):
    return {"username": user}


@router.post("/password")
async def change_password(body: PasswordIn, response: Response,
                          user: str = Depends(current_user), p: Platform = Depends(platform)):
    if not await p.auth.change_password(user, body.old, body.new):
        await audit(p, user, "change_password", ok=False)
        raise HTTPException(400, "current password is incorrect")
    await audit(p, user, "change_password")
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True, "relogin": True}
