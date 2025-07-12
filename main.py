from fastapi import FastAPI, HTTPException, Path, Request
from pydantic import BaseModel, Field
from typing import Optional
from fastapi.responses import JSONResponse
import base64
import re

app = FastAPI()

users_db = {}

# Models
class SignupRequest(BaseModel):
    user_id: str = Field(..., min_length=6, max_length=20, pattern="^[a-zA-Z0-9]+$")
    password: str = Field(..., min_length=8, max_length=20)

class UserResponse(BaseModel):
    user_id: str
    nickname: str

class MessageResponse(BaseModel):
    message: str
    user: Optional[UserResponse] = None
    cause: Optional[str] = None

# POST /signup
@app.post("/signup", response_model=MessageResponse)
def signup(request: SignupRequest):
    user_id = request.user_id
    password = request.password

    # Check if user already exists
    if user_id in users_db:
        raise HTTPException(status_code=400, detail={"message": "account creation failed", "cause": "user_id already exists"})

    # Save user
    users_db[user_id] = {
        "user_id": user_id,
        "password": password,
        "nickname": user_id  # default nickname same as user_id
    }

    return {
        "message": "account created",
        "user": {
            "user_id": user_id,
            "nickname": user_id
        }
    }


@app.get("/users/{user_id}", response_model=MessageResponse)
def get_user(user_id: str, request: Request):
    auth_header = request.headers.get("Authorization")

    if not auth_header or not auth_header.startswith("Basic "):
        return JSONResponse(status_code=401, content={"message": "authentication failed"})

    # Decode Basic Auth
    try:
        encoded_credentials = auth_header.split(" ")[1]
        decoded_bytes = base64.b64decode(encoded_credentials).decode("utf-8")
        auth_user_id, auth_password = decoded_bytes.split(":", 1)
    except Exception:
        return JSONResponse(status_code=401, content={"message": "authentication failed"})

    # Verify credentials
    user = users_db.get(user_id)
    if not user:
        return JSONResponse(status_code=404, content={"message": "no user found"})

    if user_id != auth_user_id or user["password"] != auth_password:
        return JSONResponse(status_code=401, content={"message": "authentication failed"})

    # Prepare user data
    nickname = user.get("nickname") or user["user_id"]
    comment = user.get("comment")

    user_response = {
        "user_id": user["user_id"],
        "nickname": nickname
    }

    if comment:
        user_response["comment"] = comment

    return {
        "message": "user details by user_id",
        "user": user_response
    }


# PATCH /users/{user_id}
@app.patch("/users/{user_id}", response_model=UserResponse)
def update_user(user_id: str, data: dict):
    user = users_db.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user not found")

    if "nickname" in data:
        user["nickname"] = data["nickname"]

    return {
        "user_id": user["user_id"],
        "nickname": user["nickname"]
    }

# POST /close
@app.post("/close", response_model=MessageResponse)
def close():
    return { "message": "server shutting down (not really, this is a stub)" }
