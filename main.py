from fastapi import FastAPI, HTTPException, Body, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from cryptography import fernet
import asyncio
import redis
import psycopg2
import uuid
import time
import uvicorn
import json


redis_storage = redis.Redis(host='redis', port=6379, db=0) #подключение к хранилищу для кэша


def get_connection(): #соединение с бд
    try:
        db = psycopg2.connect(
            dbname="database",
            user='pasha',
            password=2901,
            host='postgres',
            port="5432"
        )
        return db
    except Exception as err:
        return f'Error {err}'


def delete_from_db_with_logg(db, cursor, secret_key:str, action:str, ip:str): #удаление из бд секрета и логгирование события
    cursor.execute("DELETE FROM secret WHERE secret_key = %s", (secret_key,))
    db.commit()
    cursor.execute(
        "INSERT INTO logger (secret_key, action, ip_address) VALUES (%s, %s, %s)", (secret_key, action, ip))
    db.commit()


with open('fernet.key', 'rb') as file: #извечение ключа для шифрования
    fernet_key = file.read()

fernet_main = fernet.Fernet(fernet_key)


async def delete_later_secret(): #удаление просроченных секретов
    while True:
        try:
            db = get_connection()
            cursor = db.cursor()
            cursor.execute("""
                WITH delete_secret AS (
                    DELETE FROM secret WHERE ttl_seconds < %s
                    RETURNING secret_key           
                )
                INSERT INTO logger (secret_key, action) SELECT secret_key, 'expired' FROM delete_secret
            """, (int(time.time()),))
            db.commit()
            cursor.close()
            db.close()
        except Exception as err:
            print(err)
        finally:
            pass
        await asyncio.sleep(300)

class NoCache(BaseHTTPMiddleware): #запрет кэша
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.update({
            "Cache-Control":"no-store, no-cache, must-revalidate, max-age=0"
        })
        return response


async def lifespan(app: FastAPI): #запуск ассинхронно функции по удалению просроченных секретов при запуске сервера
    asyncio.create_task(delete_later_secret())
    yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(NoCache)

@app.post('/secret') #создание секрета
async def create_secret(request:Request, secret: dict = Body(...)):
    ip = str(request.client.host)

    secret_string = str(secret['secret'])
    secret_encode = fernet_main.encrypt(secret_string.encode())

    secret['secret'] = secret_encode.decode('utf-8')
    secret_encode = str(secret_encode.decode('utf-8'))

    if 'ttl_seconds' in list(secret.keys()):
        ttl_seconds = secret['ttl_seconds']
    else:
        ttl_seconds = None

    key = str(uuid.uuid4())

    if ttl_seconds != None and ttl_seconds <= 300:
        redis_storage.setex(key, ttl_seconds, json.dumps(secret))
    else:           
        redis_storage.setex(key, 300, json.dumps(secret))

    try:
        db = get_connection()
        cursor = db.cursor()
        if ('passphrase' in list(secret.keys()) and secret['passphrase'] != '') and ('ttl_seconds' in list(secret.keys()) and secret['ttl_seconds'] != ''):
            cursor.execute("INSERT INTO secret(secret_key, secret_value, passphrase, ttl_seconds) VALUES (%s, %s, %s, %s)",
                           (key, secret_encode, secret['passphrase'], int(time.time())+secret['ttl_seconds']))
        elif ('passphrase' in list(secret.keys()) and secret['passphrase'] != ''):
            cursor.execute("INSERT INTO secret(secret_key, secret_value, passphrase) VALUES (%s, %s, %s)",
                           (key, secret_encode, secret['passphrase']))
        elif ('ttl_seconds' in list(secret.keys()) and secret['ttl_seconds'] != ''):
            cursor.execute("INSERT INTO secret(secret_key, secret_value, ttl_seconds) VALUES (%s, %s, %s)",
                           (key, secret_encode, int(time.time())+secret['ttl_seconds']))
        else:
            cursor.execute("INSERT INTO secret(secret_key, secret_value) VALUES (%s, %s)",
                           (key, secret_encode))
        db.commit()

        cursor.execute(
            "INSERT INTO logger (secret_key, action, ip_address) VALUES (%s, %s, %s)", (key, 'create', ip))

        db.commit()
    except:
        raise HTTPException(status_code=999, detail="Dont add into db")
    finally:
        cursor.close()
        db.close()

    return JSONResponse(content={'secret_key': key})


@app.get('/secret/{secret_key}') #получение одноразоваого секрета
async def secret_generate(secret_key: str, request:Request):
    try:
        db = get_connection()
        cursor = db.cursor()
        ip = str(request.client.host)
        if redis_storage.exists(secret_key) == 1:
            data = json.loads(redis_storage.get(secret_key))
            secret = fernet_main.decrypt(data['secret']).decode('utf-8')
            redis_storage.delete(secret_key)
            delete_from_db_with_logg(db, cursor, secret_key, 'view and delete', ip)
            return JSONResponse(content={"secret": secret})
        else:
            cursor.execute(
                "SELECT * FROM secret WHERE secret_key = %s", (secret_key, ))
            data = cursor.fetchall()
            secret = str(data[0][2])
            secret = fernet_main.decrypt(secret).decode('utf-8')
            delete_from_db_with_logg(db, cursor, secret_key, 'view and delete', ip)
            return JSONResponse(content={"secret": secret})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'Secret not found')
    finally:
        cursor.close()
        db.close()


@app.delete('/secret/{secret_key}') #удаление секрета 
async def delete_secret(request_ip:Request, secret_key: str, request: dict = Body(...)):
    try:
        ip = str(request_ip.client.host)
        if 'passphrase' in list(request.keys()):
            passphrase = str(request['passphrase'])
        db = get_connection()
        cursor = db.cursor()
        cursor.execute(
            "SELECT * FROM secret WHERE secret_key = %s", (secret_key, ))
        data = cursor.fetchall()
        pass_data = data[0][3]
        if pass_data != None:
            if passphrase == pass_data:
                delete_from_db_with_logg(db, cursor, secret_key, 'delete', ip)
                if redis_storage.exists(secret_key) == 1:
                    redis_storage.delete(secret_key)
                return JSONResponse(content={"secret": "secret_delete"})
            else:
                raise HTTPException(status_code=422, detail="Wrong passphrase")
        else:
            delete_from_db_with_logg(db, cursor, secret_key, 'delete', ip)
            if redis_storage.exists(secret_key) == 1:
                redis_storage.delete(secret_key)
            return JSONResponse(content={'secret': 'secret_delete'})
    except:
        raise HTTPException(status_code=404, detail='Not found secret')
    finally:
        cursor.close()
        db.close()





if __name__ == '__main__': #запуск сервера
    uvicorn.run("main:app", host='0.0.0.0', port=8000, reload=True)
