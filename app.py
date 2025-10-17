from flask import Flask, render_template, request
import os
from password_checker import load_wordlist, score_password

app = Flask(__name__, static_folder='static', template_folder='templates')

# Configuration
PROJECT_ROOT = os.path.dirname(__file__)
WORDLIST_PATH = os.path.join(PROJECT_ROOT, 'data', 'common_words.txt')

# Create data directory if it doesn't exist
data_dir = os.path.join(PROJECT_ROOT, 'data')
os.makedirs(data_dir, exist_ok=True)

# Load wordlist if exists
wordlist = load_wordlist(WORDLIST_PATH)


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', result=None)


@app.route('/check', methods=['POST'])
def check_password():
    """
    Check password strength without storing the raw password.
    """
    password = request.form.get('password', '')
    use_hibp = request.form.get('use_hibp') == 'on'

    result = score_password(
        password,
        wordlist=wordlist,
        do_hibp=use_hibp
    )

    return render_template('index.html', result=result)


if __name__ == '__main__':
    # Development only - use WSGI server + TLS for production
    app.run(debug=True, host='127.0.0.1', port=5000)