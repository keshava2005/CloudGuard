from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def generate_pdf(score, risk, mfa, s3, ec2, cloudtrail):

    file_path = "reports/cloudguard_report.pdf"

    c = canvas.Canvas(file_path, pagesize=letter)

    c.setFont("Helvetica", 12)

    c.drawString(50, 750, "CloudGuard AWS Security Report")

    c.drawString(50, 720, f"Security Score: {score}")
    c.drawString(50, 700, f"Risk Level: {risk}")

    c.drawString(50, 660, f"Users Without MFA: {mfa}")
    c.drawString(50, 640, f"Public S3 Buckets: {s3}")
    c.drawString(50, 620, f"Open Security Groups: {ec2}")
    c.drawString(50, 600, f"CloudTrail Status: {cloudtrail}")

    c.save()

    return file_path