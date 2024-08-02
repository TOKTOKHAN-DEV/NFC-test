FROM python:3.11-slim

# 필요한 패키지 설치
RUN apt-get update && apt-get install -y \
    libusb-1.0-0-dev \
    libnfc-dev \
    && pip install nfcpy \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 작업 디렉토리 설정
WORKDIR /app

# 스크립트 복사
COPY nfcpy_test.py .

# 스크립트 실행
CMD ["python", "nfcpy_test.py"]
