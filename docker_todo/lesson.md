# 🐳 Docker & Docker Compose for Beginners

## Table of Contents
1. [What is Docker?](#what-is-docker)
2. [What is Docker Compose?](#what-is-docker-compose)
3. [Understanding Our Project Structure](#understanding-our-project-structure)
4. [Dockerfile Explained](#dockerfile-explained)
5. [Docker Compose File Explained](#docker-compose-file-explained)
6. [Essential Docker Commands](#essential-docker-commands)
7. [Essential Docker Compose Commands](#essential-docker-compose-commands)
8. [Step-by-Step Tutorial](#step-by-step-tutorial)

---

## What is Docker?

**Docker** is like a shipping container for your applications. Just like how shipping containers can hold different goods but fit on any ship, Docker containers can hold different applications but run on any computer.

### Key Benefits:
- ✅ **Consistency**: "It works on my machine" problem solved
- ✅ **Isolation**: Applications don't interfere with each other
- ✅ **Portability**: Runs the same everywhere
- ✅ **Efficiency**: Lightweight compared to virtual machines

### Real-World Analogy:
Think of Docker like a **lunch box**:
- Your lunch box (container) contains your food (application)
- You can take it anywhere (portable)
- It keeps your food separate from others (isolated)
- Anyone can use the same type of lunch box (standardized)

---

## What is Docker Compose?

**Docker Compose** is like a recipe book for multiple containers. Instead of cooking each dish separately, you follow one recipe that tells you how to prepare an entire meal.

### Why Use Docker Compose?
- 🍽️ **Multiple Services**: Run database + web app together
- 📝 **Easy Configuration**: One file to rule them all
- 🔄 **Reproducible**: Same setup every time
- 👥 **Team Friendly**: Share the same environment

---

## Understanding Our Project Structure

```
docker_todo/
├── main.py              # Flask web application
├── models.py            # Database models
├── config.py            # App configuration
├── requirements.txt     # Python dependencies
├── Dockerfile          # Instructions to build our app
├── docker-compose.yml  # Instructions to run multiple services
├── .env               # Environment variables
└── templates/         # HTML templates
    └── index.html
```

---

## Dockerfile Explained

A **Dockerfile** is like a recipe to build a container. Let's break down our Dockerfile:

```dockerfile
# Start with a base image (like choosing your cooking pot)
FROM python:3.11-slim

# Set working directory inside container (like choosing your kitchen counter)
WORKDIR /app

# Install system tools (like getting your cooking utensils ready)
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file (like getting your ingredient list)
COPY requirements.txt .

# Install Python packages (like buying ingredients)
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (like preparing your ingredients)
COPY . .

# Tell Docker which port to use (like setting the table)
EXPOSE 5000

# Run the application (like serving the meal)
CMD ["python", "main.py"]
```

### Dockerfile Commands Explained:

| Command | Purpose | Example |
|---------|---------|---------|
| `FROM` | Choose base image | `FROM python:3.11-slim` |
| `WORKDIR` | Set working directory | `WORKDIR /app` |
| `RUN` | Execute commands | `RUN pip install flask` |
| `COPY` | Copy files from host | `COPY . /app` |
| `EXPOSE` | Declare port | `EXPOSE 5000` |
| `CMD` | Default command to run | `CMD ["python", "app.py"]` |

---

## Docker Compose File Explained

Let's break down our `docker-compose.yml` step by step:

```yaml
# Version of Docker Compose format
version: '3.8'

# Define our services (like different courses in a meal)
services:

  # First service: PostgreSQL Database
  database:
    image: postgres:15              # Use pre-built PostgreSQL image
    environment:                    # Set environment variables
      POSTGRES_DB: todomaster       # Database name
      POSTGRES_USER: todouser       # Database username
      POSTGRES_PASSWORD: todopass123 # Database password
    ports:
      - "5432:5432"                # Map host port 5432 to container port 5432
    volumes:
      - todo_data:/var/lib/postgresql/data  # Persist database data

  # Second service: Our Flask Web Application
  web:
    build: .                       # Build from Dockerfile in current directory
    ports:
      - "5000:5000"               # Map host port 5000 to container port 5000
    environment:
      # Database connection string
      DATABASE_URL: postgresql://todouser:todopass123@database:5432/todomaster
    depends_on:
      - database                  # Start database before web app
    volumes:
      - .:/app                   # Mount current directory for development

# Define persistent storage
volumes:
  todo_data:                     # Named volume for database data
```

### Docker Compose Concepts:

#### 🏢 **Services**
Services are like different departments in a company:
- `database`: The data storage department
- `web`: The customer service department

#### 🔌 **Ports**
Port mapping is like phone extensions:
- `"5000:5000"` means: "When someone calls extension 5000, connect them to room 5000"
- Format: `"host_port:container_port"`

#### 📦 **Volumes**
Volumes are like filing cabinets:
- **Named volumes**: `todo_data` - Permanent storage managed by Docker
- **Bind mounts**: `.:/app` - Direct connection to your computer's folder

#### 🌍 **Environment Variables**
Like sticky notes with important information:
- `POSTGRES_DB=todomaster` - "The database name is todomaster"
- `POSTGRES_USER=todouser` - "The username is todouser"

#### 🔗 **Dependencies**
`depends_on` is like saying "Don't serve dessert until the main course is ready"

---

## Essential Docker Commands

### Basic Commands:

```bash
# See all running containers (like checking what's cooking)
docker ps

# See all containers (running + stopped)
docker ps -a

# See all images on your computer
docker images

# Build an image from Dockerfile
docker build -t my-app .

# Run a container
docker run -p 5000:5000 my-app

# Stop a running container
docker stop container_name

# Remove a container
docker rm container_name

# Remove an image
docker rmi image_name

# See container logs (like reading the cooking instructions)
docker logs container_name

# Enter a running container (like stepping into the kitchen)
docker exec -it container_name bash
```

### Real Examples:

```bash
# Build our todo app
docker build -t todo-app .

# Run PostgreSQL database
docker run -d \
  --name todo-db \
  -e POSTGRES_DB=todomaster \
  -e POSTGRES_USER=todouser \
  -e POSTGRES_PASSWORD=todopass123 \
  -p 5432:5432 \
  postgres:15

# Run our web app
docker run -d \
  --name todo-web \
  -p 5000:5000 \
  --link todo-db:database \
  todo-app
```

---

## Essential Docker Compose Commands

### Basic Commands:

```bash
# Start all services (like preparing the entire meal)
docker-compose up

# Start services in background
docker-compose up -d

# Stop all services
docker-compose down

# View running services
docker-compose ps

# View logs from all services
docker-compose logs

# View logs from specific service
docker-compose logs web

# Rebuild and start services
docker-compose up --build

# Stop and remove everything (including volumes)
docker-compose down -v

# Scale a service (run multiple instances)
docker-compose up --scale web=3
```

### Advanced Commands:

```bash
# Execute command in running service
docker-compose exec web bash

# Execute command in database service
docker-compose exec database psql -U todouser -d todomaster

# Follow logs in real-time
docker-compose logs -f

# Restart specific service
docker-compose restart web

# Pull latest images
docker-compose pull
```

---

## Step-by-Step Tutorial

### Step 1: Verify Prerequisites

```bash
# Check if Docker is installed
docker --version

# Check if Docker Compose is installed
docker-compose --version

# If not installed, visit: https://docs.docker.com/get-docker/
```

### Step 2: Understand the Project

```bash
# Navigate to project directory
cd /home/chatelo/Documents/Africode_Academy/docker_todo

# Look at project structure
ls -la

# Examine our Docker files
cat Dockerfile
cat docker-compose.yml
```

### Step 3: Build and Run with Docker Compose

```bash
# Start everything (first time - will build images)
docker-compose up --build

# Watch the magic happen! You'll see:
# 1. PostgreSQL database starting
# 2. Flask app building
# 3. Flask app connecting to database
# 4. Services ready at localhost:5000
```

### Step 4: Verify Everything Works

```bash
# In another terminal, check running containers
docker-compose ps

# Should show something like:
#        Name              Command               State           Ports
# ----------------------------------------------------------------
# docker_todo_database_1   docker-entrypoint.sh postgres   Up      0.0.0.0:5432->5432/tcp
# docker_todo_web_1        python main.py                   Up      0.0.0.0:5000->5000/tcp

# Test the application
curl http://localhost:5000
# Or open http://localhost:5000 in your browser
```

### Step 5: Explore the Database

```bash
# Connect to PostgreSQL database
docker-compose exec database psql -U todouser -d todomaster

# Inside PostgreSQL, try these commands:
\dt                    # List tables
SELECT * FROM todos;   # View todos
\q                     # Quit
```

### Step 6: Monitor Logs

```bash
# View all logs
docker-compose logs

# View only web app logs
docker-compose logs web

# Follow logs in real-time
docker-compose logs -f web
```

### Step 7: Make Changes and Test

```bash
# Edit main.py in your favorite editor
nano main.py

# Restart just the web service
docker-compose restart web

# Or rebuild if you changed requirements
docker-compose up --build web
```

### Step 8: Clean Up

```bash
# Stop services but keep data
docker-compose down

# Stop services and remove all data
docker-compose down -v

# Remove all unused Docker resources
docker system prune -a
```

---

## Common Issues and Solutions

### Issue 1: Port Already in Use
```bash
# Error: Port 5432 already in use
# Solution: Stop existing PostgreSQL or change port
docker-compose down
# Or change port in docker-compose.yml to "5433:5432"
```

### Issue 2: Permission Denied
```bash
# Error: Cannot connect to Docker daemon
# Solution: Add user to docker group
sudo usermod -aG docker $USER
# Then logout and login again
```

### Issue 3: Database Connection Failed
```bash
# Error: Could not connect to database
# Solution: Check if database service is running
docker-compose ps
docker-compose logs database
```

### Issue 4: Changes Not Reflected
```bash
# Problem: Code changes not showing
# Solution: Rebuild the service
docker-compose up --build web
```

---

## Best Practices

### 1. **Environment Variables**
```bash
# Never put passwords in docker-compose.yml
# Use .env file instead
echo "POSTGRES_PASSWORD=secure_password" > .env
```

### 2. **Data Persistence**
```yaml
# Always use named volumes for important data
volumes:
  - database_data:/var/lib/postgresql/data  # ✅ Good
  # - /tmp/data:/var/lib/postgresql/data    # ❌ Bad (temporary)
```

### 3. **Development vs Production**
```bash
# Use different compose files
docker-compose -f docker-compose.dev.yml up    # Development
docker-compose -f docker-compose.prod.yml up   # Production
```

### 4. **Health Checks**
```yaml
services:
  database:
    image: postgres:15
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U todouser"]
      interval: 30s
      timeout: 10s
      retries: 3
```

---

## Useful Resources

- 📚 [Official Docker Documentation](https://docs.docker.com/)
- 🐳 [Docker Hub](https://hub.docker.com/) - Find pre-built images
- 📖 [Docker Compose Documentation](https://docs.docker.com/compose/)
- 🎓 [Interactive Docker Tutorial](https://www.docker.com/play-with-docker)
- 🔧 [Docker Desktop](https://www.docker.com/products/docker-desktop) - GUI for Docker

---

## Summary

**Docker** helps you package your application so it runs anywhere.
**Docker Compose** helps you run multiple containers together easily.

Think of it like this:
- **Dockerfile** = Recipe for one dish
- **Docker Compose** = Menu for entire restaurant
- **Container** = Served dish
- **Image** = Recipe template

With our todo app:
- We have 2 services: database (PostgreSQL) + web app (Flask)
- They talk to each other through Docker's network
- Data persists even if containers restart
- Everything starts with one command: `docker-compose up`

**Next Steps:**
1. Try modifying the docker-compose.yml
2. Add a Redis cache service
3. Create different environments (dev, staging, prod)
4. Learn about Docker networks and security
5. Explore Docker Swarm for scaling

Happy Dockerizing! 🐳✨