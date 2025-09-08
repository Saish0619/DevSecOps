FROM python:3.10-slim

# Install dependencies
RUN pip install sslyze
RUN pip install idna
RUN pip install dnspython

# Copy the script
WORKDIR /app

COPY SSLyze_DevSecOps.py /app/SSLyze_DevSecOps.py

# Run the script with URL argument
ENTRYPOINT ["python", "SSLyze_DevSecOps.py"]
