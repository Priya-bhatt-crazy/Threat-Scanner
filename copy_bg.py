import shutil
import os

src = r"C:\Users\parma\.gemini\antigravity\brain\12c479cf-136d-4d8d-a7e4-047522656ba9\cyber_login_bg_1782758360473.png"
dst_dir = r"d:\OSF Hackathon1\OSF Hackathon1\frontend\public"
dst = os.path.join(dst_dir, "cyber_login_bg.png")

os.makedirs(dst_dir, exist_ok=True)
shutil.copy(src, dst)
print("Background image successfully copied to:", dst)
