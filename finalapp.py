import os
import subprocess
from flask import Flask, request, render_template, send_file, flash, redirect
import zipfile

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Path to OpenSSL executable
OPENSSL_PATH = "openssl"  # Update if needed (e.g., "C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/generate-csr", methods=["POST"])
def generate_csr():
    try:
        country = request.form["country"]
        state = request.form["state"]
        locality = request.form["locality"]
        organization = request.form["organization"]
        org_unit = request.form.get("org_unit", "")
        common_name = request.form["common_name"]
        rsa_size = request.form["rsa_size"]

        # Define file names
        key_filename = f"{common_name}_key.pem"
        csr_filename = f"{common_name}.csr"
        zip_filename = f"{common_name}_CSR_and_Key.zip"

        # OpenSSL command to generate CSR and private key
        command = [
            OPENSSL_PATH, "req", "-new", "-newkey", f"rsa:{rsa_size}", "-nodes", "-keyout",
            key_filename, "-out", csr_filename, "-subj",
            f"/C={country}/ST={state}/L={locality}/O={organization}/OU={org_unit}/CN={common_name}",
        ]
        subprocess.run(command, check=True)

        # Create a ZIP file containing both CSR and Key
        with zipfile.ZipFile(zip_filename, "w") as zipf:
            zipf.write(key_filename)
            zipf.write(csr_filename)

        flash("CSR and Key generated successfully!", "success")
        return send_file(zip_filename, as_attachment=True)

    except Exception as e:
        flash(f"Error generating CSR: {e}", "danger")
        return redirect("/")


@app.route("/convert-pfx", methods=["POST"])
def convert_pfx():
    try:
        if "pfx_file" not in request.files:
            flash("No PFX file uploaded!", "danger")
            return redirect("/")

        pfx_file = request.files["pfx_file"]
        pfx_password = request.form.get("pfx_password", "")

        # Save uploaded PFX file
        pfx_filename = "uploaded.pfx"
        pfx_file.save(pfx_filename)

        cer_filename = "certificate.cer"

        # OpenSSL command to convert PFX to certificate
        command = [OPENSSL_PATH, "pkcs12", "-in", pfx_filename, "-nokeys", "-out", cer_filename]
        if pfx_password:
            command.extend(["-passin", f"pass:{pfx_password}"])

        subprocess.run(command, check=True)

        flash("PFX file converted successfully!", "success")
        return send_file(cer_filename, as_attachment=True)

    except Exception as e:
        flash(f"Error converting PFX: {e}", "danger")
        return redirect("/")


@app.route("/generate-pfx", methods=["POST"])
def generate_pfx():
    try:
        if "cert_file" not in request.files or "key_file" not in request.files:
            flash("Please upload both certificate and key files!", "danger")
            return redirect("/")

        cert_file = request.files["cert_file"]
        key_file = request.files["key_file"]
        pfx_password = request.form["pfx_password"]

        # Save uploaded files
        cert_filename = "uploaded_cert.pem"
        key_filename = "uploaded_key.pem"
        pfx_filename = "output.pfx"

        cert_file.save(cert_filename)
        key_file.save(key_filename)

        # OpenSSL command to generate PFX file
        command = [
            OPENSSL_PATH, "pkcs12", "-export", "-in", cert_filename, "-inkey", key_filename, "-out", pfx_filename,
            "-passout", f"pass:{pfx_password}",
        ]
        subprocess.run(command, check=True)

        flash("PFX file generated successfully!", "success")
        return send_file(pfx_filename, as_attachment=True)

    except Exception as e:
        flash(f"Error generating PFX: {e}", "danger")
        return redirect("/")


@app.route("/check-files", methods=["POST"])
def check_files():
    try:
        if "csr_file" not in request.files or "key_file" not in request.files or "cert_file" not in request.files:
            flash("Please upload CSR, Key, and Certificate files!", "danger")
            return redirect("/")

        csr_file = request.files["csr_file"]
        key_file = request.files["key_file"]
        cert_file = request.files["cert_file"]

        csr_filename = "uploaded_csr.csr"
        key_filename = "uploaded_key.pem"
        cert_filename = "uploaded_cert.pem"

        csr_file.save(csr_filename)
        key_file.save(key_filename)
        cert_file.save(cert_filename)

        # Extract modulus from CSR, Key, and Certificate
        csr_modulus = subprocess.check_output([OPENSSL_PATH, "req", "-noout", "-modulus", "-in", csr_filename]).strip()
        key_modulus = subprocess.check_output([OPENSSL_PATH, "rsa", "-noout", "-modulus", "-in", key_filename]).strip()
        cert_modulus = subprocess.check_output([OPENSSL_PATH, "x509", "-noout", "-modulus", "-in", cert_filename]).strip()

        if csr_modulus == key_modulus == cert_modulus:
            flash("Files match successfully!", "success")
        else:
            flash("Files do not match!", "danger")

        return redirect("/")

    except Exception as e:
        flash(f"Error checking files: {e}", "danger")
        return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)
