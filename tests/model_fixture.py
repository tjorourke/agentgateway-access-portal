"""Test-only OpenAI-compatible response; no provider calls or credentials."""
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.post('/v1/chat/completions')
def chat():
    return jsonify(id='fixture-response', object='chat.completion', created=0,
                   model=request.json.get('model', 'test-model'),
                   choices=[{'index':0,'message':{'role':'assistant','content':'OK'},'finish_reason':'stop'}],
                   usage={'prompt_tokens':100,'completion_tokens':20,'total_tokens':120})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
