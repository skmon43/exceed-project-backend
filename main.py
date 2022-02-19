from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Request, status, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder

from datetime import datetime, date, time, timedelta


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
    people_to_close : int
    people_to_reopen : int



@app.get("/")
async def get_root():
    return {"detail": "this is root ('/')"}

@app.post("/event_add")
async def add_event(event: Event, current_user: User = Depends(get_current_user)):
    event.start = f'{event.start}:00'
    event.end = f'{event.end}:00'
    
    for x in db['events'].find():
        if event.title == x["title"]:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail = f"didn't add event - title is duplicate from tilte in DB")

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

    db["events"].insert_one(jsonable_encoder(event))
    return {"detail": "successfully add event"}



@app.put("/event_update/{title}")
async def event_edit(title : str, event : Event, current_user: User = Depends(get_current_user)):
    query = {"title" : title}
    find = db["events"].find_one(query)
    
    if (find != None):
        new = {"$set": {"title" : event.title , "date" : event.date , "start" : event.start , "end" : event.end , "people_to_close" : event.people_to_close , "people_to_reopen" : event.people_to_reopen}}
        db["events"].update_one(query,new)
        return {
            "detail" : "successfully update event"
        }
    else:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail = f"title is not exist in DB")



@app.delete("/event_del/{title}")
async def event_delete(title : str, current_user: User = Depends(get_current_user)):
    query = {"title" : title}
    find = db["events"].find_one(query)

    if (find != None):
        db["events"].delete_one(query)
        return {
            "detail" : "successfully delete event"
        }
    else:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail = f"title is not exist in DB")



@app.get("/event")
async def all_event_info():
    event_list = []
    find = db["events"].find({}, {"_id":0})
    for x in find:
        event_list.append(x)
    return event_list



@app.get("/event/{title}")
async def event_info(title: str):
    return db["events"].find_one({"title": title}, {"_id":0})


@app.get("/event_now")
async def now_event_info():
    date_today = f'{date.today()}'

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
            now_event = db["events"].find_one({"_id": x["_id"]}, {"_id": 0})
            return now_event
    
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail = f"no event now")



@app.get("/event_next")
async def next_event_info():
    date_date = date.today()
    
    now_time = datetime.now().strftime("%H:%M:%S")
    nt = now_time.split(":")
    now_time = time(int(nt[0]), int(nt[1]), int(nt[2]))

    for i in range (365):
        date_date_str = f'{date_date}'

        date_today_str = f'{date.today()}'

        query = {"date": date_date_str}
        find = db["events"].find(query).sort("start")

        for x in find:
            now_time = datetime.now().strftime("%H:%M:%S")
            nt = now_time.split(":")
            now_time = time(int(nt[0]), int(nt[1]), int(nt[2]))

            x_start = x["start"]
            xs = x_start.split(":")
            x_start = time(int(xs[0]), int(xs[1]), int(xs[2]))

            if ((date_date_str == date_today_str) and (x_start > now_time)) or (date_date_str != date_today_str):              
                return db["events"].find_one({"title": x["title"]}, {"_id": 0})

        date_date = date_date + timedelta(days = 1)

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail = f"no events comming in 1-year")


class People(BaseModel):
    people_in: int
    people_out: int
    chair_status: str

the_people = {
        "current_people": 0,
        "chair_status": 0
    }

@app.post("/hardware_in_out")
async def in_out_people(people: People):
    chair = people.chair_status.split(" ")
    print(chair)
    global the_people
    the_people = {
        "current_people": people.people_in - people.people_out,
        "chair_status": chair
    }
    return {"detail": "successfully updated people info"}



@app.get("/front_people")
async def now_people_info():
    try:
        the_people
    except NameError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail = f"no people info")
    else:
        return the_people



@app.get("/hardware") 
async def current():
    try:
        the_people
    except NameError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail = f"no people info")
    else:
        return {
            "current_people": the_people["current_people"]
        }



@app.get("/people_in_time")
async def door_status():
    try:
        current = the_people["current_people"]
    except NameError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail = f"no people info")

    date_today = f'{date.today()}'
    now_time = datetime.now().strftime("%H:%M:%S")
    nt = now_time.split(":")
    now_time = time(int(nt[0]), int(nt[1]), int(nt[2]))
    find = db["events"].find({"date": date_today})
    print(date_today)
    if (find != None):
        for x in find:
            x_st = x["start"].split(":")
            x_start_time = time(int(x_st[0]), int(x_st[1]), int(x_st[2]))

            x_et = x["end"].split(":")
            x_end_time = time(int(x_et[0]), int(x_et[1]), int(x_et[2]))

            if (x_start_time < now_time < x_end_time):
                if (current < x["people_to_close"]):
                    return {
                        "status": 1 #คนยังไม่ถึง max
                    }
                else:
                    return {
                        "status": 0
                    }
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail = f"no event info") 



@app.get("/statistic")
async def statistic():
    pass



class History(BaseModel):
    event_id: str
    date: str
    start_end: str
    people_count: int

@app.get("/hit_me")
async def count_when_the_end():
    date_today = f'{date.today()}'

    find = db["events"].find({"date": date_today})
    for x in find:
        now_time = datetime.now().strftime("%H:%M:%S")
        print(f'now_time={now_time}, this_end_time={x["end"]}')
        if f'{now_time}' == f'{x["end"]}':
            new = {
                "event_id": x["_id"],
                "date": date_today,
                "start": x["start"],
                "end": x["end"],
                "people_count": the_people["current_people"]
            }
            db["historys"].insert_one(new)
            return {"detail": "successfully add history"}