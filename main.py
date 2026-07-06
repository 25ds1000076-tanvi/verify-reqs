from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import jwt  # PyJWT

app = FastAPI()

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-u0u1x5mo.apps.exam.local"


@app.get("/")
async def root():
    # simple health check so you can confirm the deployment is alive
    return {"status": "ok", "endpoint": "/verify"}


@app.post("/verify")
async def verify(request: Request):
    try:
        body = await request.json()
        token = body.get("token", "")
    except Exception:
        return JSONResponse(status_code=401, content={"valid": False})

    try:
        claims = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
        )
        # Signature, issuer, audience, and expiry all passed if we reach here
        return {
            "valid": True,
            "email": claims.get("email"),
            "sub": claims.get("sub"),
            "aud": claims.get("aud"),
        }
    except jwt.PyJWTError:
        # Catches: bad signature, expired token, wrong issuer,
        # wrong audience, tampered/malformed token — all at once
        return JSONResponse(status_code=401, content={"valid": False})
