# VULNERABLE: InjectSsti — user input passed directly to render_template_string (SSTI)
# Rule: InjectSstiTemplate | CWE-94 | Severity: CRITICAL

from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route('/greet', methods=['GET'])
def greet():
    """Render a personalised greeting using the user's name."""
    name = request.args.get('name', 'World')

    # <-- VULNERABLE: user input rendered as a Jinja2 template
    # An attacker can pass: {{ config.SECRET_KEY }} or {{ ''.__class__.__mro__[1].__subclasses__() }}
    # to read secrets or achieve remote code execution.
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)


@app.route('/render', methods=['POST'])
def render_custom():
    """Render a user-supplied template fragment."""
    user_input = request.form.get('template', '')

    # <-- VULNERABLE: direct user input as template string
    return render_template_string(user_input)


if __name__ == '__main__':
    app.run()
