import os
import json
import base64
from flask import Flask, render_template, request, redirect, url_for, flash, make_response
import jwt

app = Flask(__name__)
app.secret_key = os.urandom(24)

# namerno nesigurna konfiguracija
JWT_SECRET = "weak_secret" # ranjivost -> slab secret (lagan brute force)
PUBLIC_KEY_PATH = "public.pem"

def decode_header(token: str) -> dict:
    # rucno izvlaci header bez verifikacije
    try:
        header_b64 = token.split(".")[0]
        header_b64 += "=" * (4 - len(header_b64) % 4)  # padding
        return json.loads(base64.urlsafe_b64decode(header_b64))
    except Exception:
        return {}
    
def verify_jwt_vulnerable(token: str):
    """
    SAMO ZA DEMONSTRACIJU
    namerne ranjivosti:
        - prihvata alg=none
        - prihvata prazan potpis
        - algorithm confusion (rs256 -> hs256)
        - koristi javni kljuc za hmac secret
    """

    if not token:
        return None, "No token provided"
    
    header = decode_header(token)
    alg = header.get("alg", "HS256").lower()

    # alg=none / prazan signature
    if alg == "none" or token.endswith(".") or token.split(".")[-1] == "":
        try:
            payload_b64 = token.split(".")[1]
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            return payload, "Verified: alg=none or empty signature accepted"
        except Exception as e:
            return None, f"Invalid payload: {e}"
        
    # algorithm confusion (rs256 -> hs256)
    if alg == "hs256":
        try:
            if os.path.exists(PUBLIC_KEY_PATH):
                with open(PUBLIC_KEY_PATH, "r") as f:
                    pubkey_as_secret = f.read().encode()  

                import hmac as hmaclib
                import hashlib

                parts = token.split(".")
                signing_input = (parts[0] + "." + parts[1]).encode()
                
                sig_b64 = parts[2]

                sig_b64 += "=" * (4 - len(sig_b64) % 4)
                expected_sig = base64.urlsafe_b64decode(sig_b64)

                actual_sig = hmaclib.new(pubkey_as_secret, signing_input, hashlib.sha256).digest()

                if hmaclib.compare_digest(actual_sig, expected_sig):
                    payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                    return payload, "Verified: HS256 with public key as secret (Algorithm confusion)"
                else:
                    return None, "HS256 verification failed: invalid signature"
        except Exception as e:
            return None, f"HS256 verification failed: {e}"
        
    # standardni hs256 (bruteforce)
    try:
        payload = jwt.decode(token, key="JWT_SECRET", algorithms=["HS256"])
        return payload, "Verified: Standart HS256"
    except jwt.ExpiredSignatureError:
        return None, "Token expired"
    except jwt.InvalidSignatureError:
        return None, "Invalid signature"
    except Exception as e:
        return None, "Verification failed: {e}"
    
# ROUTES

@app.route("/")
def index():
    token = request.cookies.get("jwt_token")
    if token:
        payload, _ = verify_jwt_vulnerable(token)
        if payload:
            return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if username and password:
            payload = {"sub": username, "role": "admin" if username == "admin" else "user"}
            token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
            resp = make_response(redirect(url_for("dashboard")))
            resp.set_cookie("jwt_token", token, httponly=False, samesite="Lax")
            flash("Login successful!", "success")
            return resp
        flash("Enter username & password", "error")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    token = request.cookies.get("jwt_token")
    payload, msg = verify_jwt_vulnerable(token)
    if not payload:
        flash(msg, "error")
        return redirect(url_for("login"))
    return render_template("dashboard.html", payload=payload, token=token, msg=msg)

@app.route("/debug")
def debug():
    token = request.args.get("token", "")
    result = {"header": {}, "payload": {}, "status": "", "raw": token}
    if token:
        result["header"] = decode_header(token)
        try:
            p_b64 = token.split(".")[1]
            p_b64 += "=" * (4 - len(p_b64) % 4)
            result["payload"] = json.loads(base64.urlsafe_b64decode(p_b64))
        except Exception:
            result["payload"] = "Invalid base64"
        payload, msg = verify_jwt_vulnerable(token)
        result["status"] = msg
        result["verified_payload"] = payload
    return render_template("debug.html", result=result)

@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login")))
    resp.set_cookie("jwt_token", "", expires=0)
    flash("Logged out", "info")
    return resp

if __name__ == "__main__":
    # generise rsa kljuceve za alg confusion test
    if not os.path.exists("private.pem"):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        pk = rsa.generate_private_key(65537, 2048)
        with open("private.pem", "wb") as f:
            f.write(pk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        with open("public.pem", "wb") as f:
            f.write(pk.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        print("Generated RSA key pair")
    app.run(host="0.0.0.0", port=5010, debug=True)