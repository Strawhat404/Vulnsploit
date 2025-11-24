FROM python:3.11-slim

# Keep Python output unbuffered (helps with logging)
ENV PYTHONUNBUFFERED=1

# Set working directory inside the container
WORKDIR /app

#install system dependencies

RUN apt-get update && apt-get install -y nmap && apt-get clean
# Copy only requirements first so we can take advantage of Docker cache
COPY requirements.txt .

# Upgrade pip and install Python dependencies
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the rest of the backend source into the container
COPY . .

# Default command when container starts (we'll override in docker-compose)
CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py runserver 0.0.0.0:8000"]
