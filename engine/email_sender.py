import yagmail
import streamlit as st

def send_email(receiver_email, pdf_path):

    sender_email = st.secrets["email"]["sender_email"]
    sender_password = st.secrets["email"]["sender_password"]

    yag = yagmail.SMTP(sender_email, sender_password)

    yag.send(
        to=receiver_email,
        subject="CloudGuard AWS Security Report",
        contents="Your AWS security scan report is attached.",
        attachments=pdf_path
    )