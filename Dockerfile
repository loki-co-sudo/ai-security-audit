FROM python:3.11-slim

# tkinter と X11 クライアントライブラリ（GUIに必要）
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-tk \
    tk-dev \
    libx11-6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p reports

# 起動方法（X11フォワーディングが必要）:
#   Windows: VcXsrv または WSLg を起動後に
#     docker run -e DISPLAY=host.docker.internal:0.0 ai-security-audit
#   Linux:
#     docker run -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix ai-security-audit
CMD ["python", "main.py"]
