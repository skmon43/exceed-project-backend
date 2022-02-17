from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Request, status, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder

from datetime import datetime, date, time, timedelta
from time import sleep

app = FastAPI()
origins = [
    "http://localhost:8080",
    "http://localhost:3000"
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from pymongo import MongoClient
client = MongoClient("mongodb://localhost", 27017)
db = client["Project"]


# Hashing ***********************************************************************
from passlib.context import CryptContext

pwd_cxt = CryptContext(schemes =["bcrypt"],deprecated="auto")

class Hash():
    def bcrypt(password:str):
        return pwd_cxt.hash(password)
    def verify(hashed,normal):
        return pwd_cxt.verify(normal,hashed)
# *******************************************************************************



# Oauth *************************************************************************
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    return verify_token(token,credentials_exception)
# *******************************************************************************



# Jwttoken **********************************************************************
from jose import JWTError, jwt

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token:str,credentials_exception):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
# *******************************************************************************



# Users *************************************************************************
class User(BaseModel):
    username: str
    password: str
class Login(BaseModel):
    username: str
    password: str
class Token(BaseModel):
    access_token: str
    token_type: str
class TokenData(BaseModel):
    username: Optional[str] = None

# @app.get("/")
# def read_root(current_user: User = Depends(get_current_user)):
#     return {"data":"Hello World"}

@app.post('/register')
def create_user(request: User):
    hashed_pass = Hash.bcrypt(request.password)
    user_object = dict(request)
    user_object["password"] = hashed_pass
    user_id = db["users"].insert_one(user_object)
    # print(user)
    return {"res":"created"}

@app.post('/login')
def login(request:OAuth2PasswordRequestForm = Depends()):       # request format: x-www-form-urlencoded (username, password)
    user = db["users"].find_one({"username": request.username})
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail = f'No user found with this {request.username} username')
    if not Hash.verify(user["password"],request.password):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail = f'Wrong Username or password')
    access_token = create_access_token(data={"sub": user["username"] })
    return {"access_token": access_token, "token_type": "bearer"}
# *******************************************************************************



# APIs **************************************************************************
class Event(BaseModel):
    title: str
    date: str
    start: str
    end: str
    duration_time: int  #minutes
    break_time : int    #minutes
    people_to_close : int
    people_to_reopen : int
    schedule: Optional[list] = None
    sch_people: Optional[list] = None



@app.get("/")
def get_root():
    return {"detail": "this is root directory (/)"}

@app.post("/admin_event")
def add_event(event: Event, current_user: User = Depends(get_current_user)):
    st = event.start.split(":")
    start_time = time(int(st[0]), int(st[1]), int(st[2]))

    et = event.end.split(":")
    end_time = time(int(et[0]), int(et[1]), int(et[2]))
    
    query = {"date": event.date}
    find = db["events"].find(query)

    for x in find:
        x_st = x["start"].split(":")
        x_start_time = time(int(x_st[0]), int(x_st[1]), int(x_st[2]))

        x_et = x["end"].split(":")
        x_end_time = time(int(x_et[0]), int(x_et[1]), int(x_et[2]))

        if (start_time < x_start_time < end_time) or (start_time < x_end_time < end_time):  
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail = f"didn't add event - time is overlap from time in DB")  
        if (start_time >= x_start_time) and (end_time <= x_end_time):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail = f"didn't add event - time is overlap from time in DB")  
        if (start_time < x_start_time) and (end_time > x_end_time):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail = f"didn't add event - time is overlap from time in DB")  

    left_t = datetime(2000, 1, 1, int(st[0]), int(st[1]), int(st[2]))
    right_t = left_t + timedelta(minutes = event.duration_time)
    end_t = datetime(2000, 1, 1, int(et[0]), int(et[1]), int(et[2]))

    schedule_list = []
    sch_people_dict = {}
    schedule_list.append(f'{left_t.time()}-{right_t.time()}')
    sch_people_dict[f'{left_t.time()}-{right_t.time()}'] = None
    while (left_t + timedelta(minutes = (event.duration_time + event.break_time)) < end_t):
        left_t = left_t + timedelta(minutes = (event.duration_time + event.break_time))
        right_t = left_t + timedelta(minutes = event.duration_time)
        schedule_list.append(f'{left_t.time()}-{right_t.time()}')
        sch_people_dict[f'{left_t.time()}-{right_t.time()}'] = None

    event.schedule = schedule_list
    event.sch_people = sch_people_dict

    db["events"].insert_one(jsonable_encoder(event))
    return {"detail": "successfully add event"}



@app.get("/front_event")
def now_event_info():
    date_today = f'{date.today()}'
    dt = date_today.split("-")
    date_today = f'{dt[2]}:{dt[1]}:{dt[0]}'

    now_time = datetime.now().strftime("%H:%M:%S")
    nt = now_time.split(":")
    now_time = time(int(nt[0]), int(nt[1]), int(nt[2]))

    print(date_today)
    print(now_time)

    find = db["events"].find({"date": date_today})

    for x in find:
        x_st = x["start"].split(":")
        x_start_time = time(int(x_st[0]), int(x_st[1]), int(x_st[2]))

        x_et = x["end"].split(":")
        x_end_time = time(int(x_et[0]), int(x_et[1]), int(x_et[2]))

        if (x_start_time < now_time < x_end_time):
            next_round_time = datetime(2000, 1, 1, int(x_et[0]), int(x_et[1]), int(x_et[2]))
            while (next_round_time < datetime.now()):
                next_round_time = next_round_time + timedelta(minutes = (x["duration_time"] + x["break_time"]))

            current_round_time = next_round_time - timedelta(minutes = (x["duration_time"] + x["break_time"]))
            end_current_round_time = current_round_time + timedelta(minutes = x["duration_time"])

            if current_round_time.time() < now_time < end_current_round_time.time():
                now = f'{current_round_time.time()}-{end_current_round_time.time()}'
            else:
                now = None

            return {
                "title": x["title"],
                "date": date_today,
                "now": now,
                "next": next_round_time.time()
            }
    
    return {
        "detail": "no event now"
    }



class People(BaseModel):
    people_in: int
    people_out: int
    chair_status: str

@app.post("/hardware_in_out")
def in_out_people(people: People):
    chair = people.chair_status.split(" ")
    print(chair)
    global the_people
    the_people = {
        "current_people": people.people_in - people.people_out,
        "chair_status": chair
    }
    return {"detail": "successfully updated people info"}



@app.get("/front_people")
def now_people_info():
    try:
        the_people
    except NameError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail = f"no people info")
    else:
        return the_people



@app.get("/hardware") 
def current():
    try:
        the_people
    except NameError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail = f"no people info")
    else:
        return {
            "current_people": the_people["current_people"]
        }



@app.get("/statistic")
def people_coun():
    pass



class History(BaseModel):
    date: str
    start_end: str
    people_count: int

async def count_when_the_end():
    date_today = f'{date.today()}'
    dt = date_today.split("-")
    date_today = f'{dt[2]}:{dt[1]}:{dt[0]}'

    find = db["events"].find({"date": date_today})
    for x in find:
        # print(x)
        for y in x["schedule"]:
            time_len = y.split("-")
            this_end_time = time_len[1]
            now_time = datetime.now().strftime("%H:%M:%S")
            print(f'now_time={now_time}, this_end_time={this_end_time}')
            if f'{now_time}' == f'{this_end_time}':
                new = {
                    "date": date_today,
                    "start_end": y,
                    "people_count": the_people["current_people"]
                }
                db["historys"].insert_one(new)
                return {"detail": "successfully add history"}

# @app.get("/do")
# async def keep_count(background_task: BackgroundTasks):
#     background_task.add_task(count_when_the_end)
#     return {"detail": "working in background"}

# while True:
#     count_when_the_end()              