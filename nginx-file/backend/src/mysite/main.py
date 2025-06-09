from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

todos = []  # In-memory store
id_counter = 1  # Simulated auto-incrementing ID


class Todo(BaseModel):
    text: str


class TodoItem(Todo):
    id: int


@app.get("/todos", response_model=List[TodoItem])
def get_todos():
    return todos


@app.post("/todos", response_model=TodoItem)
def create_todo(todo: Todo):
    global id_counter
    todo_item = TodoItem(id=id_counter, text=todo.text)
    todos.append(todo_item)
    id_counter += 1
    return todo_item


@app.put("/todos/{todo_id}", response_model=TodoItem)
def update_todo(todo_id: int, updated: Todo):
    for todo in todos:
        if todo.id == todo_id:
            todo.text = updated.text
            return todo
    raise HTTPException(status_code=404, detail="Todo not found")


@app.delete("/todos/{todo_id}")
def delete_todo(todo_id: int):
    global todos
    for todo in todos:
        if todo.id == todo_id:
            todos = [t for t in todos if t.id != todo_id]
            return {"message": "Deleted"}
    raise HTTPException(status_code=404, detail="Todo not found")
