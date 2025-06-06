FROM python
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY fernet.key ./
COPY . .
CMD [ "python", "main.py" ]