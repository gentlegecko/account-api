from fastapi import FastAPI, HTTPException, Request, Path, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict
import base64

app = FastAPI()
users_db: Dict[str, Dict] = {}

class SignupRequest(BaseModel):
    user_id: str = Field(..., min_length=6, max_length=20, pattern="^[a-zA-Z0-9]+$")
    password: str = Field(..., min_length=8, max_length=20)

class UserResponse(BaseModel):
    user_id: str
    nickname: str
    comment: Optional[str] = None

class MessageResponse(BaseModel):
    message: str
    user: Optional[UserResponse] = None
    cause: Optional[str] = None


def get_auth_user(request: Request) -> Optional[Dict]:
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(auth[6:]).decode()
        user_id, password = decoded.split(":", 1)
        user = users_db.get(user_id)
        if user and user["password"] == password:
            return {"user_id": user_id, "user": user}
    except Exception:
        pass
    return None


@app.post("/signup", response_model=MessageResponse)
def signup(req: SignupRequest):
    if req.user_id in users_db:
        raise HTTPException(400, detail={"message": "Account creation failed", "cause": "required user_id and password"})
    users_db[req.user_id] = {"user_id": req.user_id, "password": req.password, "nickname": req.user_id}
    return {
        "message": "Account successfully created",
        "user": {"user_id": req.user_id, "nickname": req.user_id}
    }

@app.get("/users/{user_id}", response_model=MessageResponse)
def get_user(user_id: str, request: Request):
    auth = get_auth_user(request)
    if not auth:
        return JSONResponse(status_code=401, content={"message": "Authentication failed"})
    if user_id not in users_db:
        return JSONResponse(status_code=404, content={"message": "No user found"})
    
    user = users_db[user_id]
    user_data = {
        "user_id": user["user_id"],
        "nickname": user.get("nickname", user_id)
    }
    if "comment" in user:
        user_data["comment"] = user["comment"]
    return {"message": "User details by user_id", "user": user_data}

@app.patch("/users/{user_id}")
def update_user(user_id: str, request: Request, body: dict = Body(...)):
    auth = get_auth_user(request)
    if not auth:
        return JSONResponse(status_code=401, content={"message": "Authentication failed"})
    if user_id not in users_db:
        return JSONResponse(status_code=404, content={"message": "No user found"})
    if auth["user_id"] != user_id:
        return JSONResponse(status_code=403, content={"message": "No Permission for update"})

    if "user_id" in body or "password" in body:
        return JSONResponse(status_code=400, content={"message": "User updation failed", "cause": "not updatable user_id and password"})
    if "nickname" not in body and "comment" not in body:
        return JSONResponse(status_code=400, content={"message": "User updation failed", "cause": "required nickname or comment"})

    user = users_db[user_id]
    if "nickname" in body:
        nickname = body["nickname"]
        user["nickname"] = user_id if nickname == "" else nickname[:30]
    if "comment" in body:
        comment = body["comment"]
        if comment == "":
            user.pop("comment", None)
        else:
            user["comment"] = comment[:100]

    return {
        "message": "User successfully updated",
        "recipe": [{
            "nickname": user.get("nickname", user_id),
            "comment": user.get("comment", "")
        }]
    }

@app.post("/close")
def close_account(request: Request):
    auth = get_auth_user(request)
    if not auth:
        return JSONResponse(status_code=401, content={"message": "Authentication failed"})
    del users_db[auth["user_id"]]
    return {"message": "Account and user successfully removed"}
