FROM python:3.8

WORKDIR /app

COPY api/ .

RUN pip install flask bcrypt

EXPOSE 5000

CMD ["python", "app.py"]