import json

def get_produtos():
    with open('produtos.json', 'r',encoding="utf-8") as f:
        produtos = json.load(f)
    return produtos
