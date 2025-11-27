import os

def insecure_eval(user_input):
    password = "hunter2"
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return eval(user_input)
