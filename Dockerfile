FROM python:3

WORKDIR /src/server

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

WORKDIR .

CMD [ "python", "server.py" ]