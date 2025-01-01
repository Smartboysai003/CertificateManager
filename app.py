from flask import Flask, request, render_template, send_file, flash
import os
import subprocess
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'outputs'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate-csr', methods=['POST'])
def generate_csr():
    data = request.form
    output_dir = OUTPUT_FOLDER

    private_key_file = os.path.join(output_dir, "private.key")
    csr_file = os.path.join(output_dir, "request.csr")
    openssl_path = "openssl"

    openssl_cmd = [
        openssl_path, "req", "-new", "-newkey", "rsa:2048", "-nodes",
        "-keyout", private_key_file, "-out", csr_file,
        "-subj", f"/C={data['country']}/ST={data['state']}/L={data['locality']}/O={data['organization']}/OU={data.get('organizationalUnit', '')}/CN={data['commonName']}"
    ]

    try:
        subprocess.run(openssl_cmd, check=True)
        flash(f"CSR and Key generated. CSR File: {csr_file}")
        return send_file(csr_file, as_attachment=True)
    except Exception as e:
        flash(f"Error generating CSR: {e}")
        return "Failed", 500

@app.route('/convert-pfx', methods=['POST'])
def convert_pfx():
    pfx_file = request.files['pfxFile']
    password = request.form['pfxPassword']
    pfx_path = os.path.join(UPLOAD_FOLDER, secure_filename(pfx_file.filename))
    pfx_file.save(pfx_path)

    cer_file = os.path.join(OUTPUT_FOLDER, "output.cer")
    openssl_cmd = ["openssl", "pkcs12", "-in", pfx_path, "-out", cer_file, "-nodes", "-password", f"pass:{password}"]

    try:
        subprocess.run(openssl_cmd, check=True)
        flash("Converted PFX to CER!")
        return send_file(cer_file, as_attachment=True)
    except Exception as e:
        flash(f"Error converting PFX to CER: {e}")
        return "Failed", 500

@app.route('/generate-pfx', methods=['POST'])
def generate_pfx():
    private_key = request.files['privateKeyFile']
    certificate = request.files['certificateFile']
    password = request.form['pfxPassword']

    private_key_path = os.path.join(UPLOAD_FOLDER, secure_filename(private_key.filename))
    certificate_path = os.path.join(UPLOAD_FOLDER, secure_filename(certificate.filename))
    private_key.save(private_key_path)
    certificate.save(certificate_path)

    pfx_file = os.path.join(OUTPUT_FOLDER, "output.pfx")
    openssl_cmd = ["openssl", "pkcs12", "-export", "-out", pfx_file, "-inkey", private_key_path, "-in", certificate_path, "-password", f"pass:{password}"]

    try:
        subprocess.run(openssl_cmd, check=True)
        flash("Generated PFX file!")
        return send_file(pfx_file, as_attachment=True)
    except Exception as e:
        flash(f"Error generating PFX: {e}")
        return "Failed", 500

if __name__ == "__main__":
    app.run(debug=True)
