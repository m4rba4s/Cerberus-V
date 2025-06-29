#!/bin/bash

echo "=== CERBERUS БЕЗОПАСНЫЙ РЕЖИМ ==="
echo "Этот режим НЕ использует системные ресурсы"
echo "Никаких VPP/eBPF операций не выполняется"
echo ""

# Проверка что мы в правильной директории
if [ ! -f "backend/main.py" ]; then
    echo "Ошибка: Запустите из директории gui/"
    exit 1
fi

# Создание виртуального окружения если его нет
if [ ! -d "backend/venv" ]; then
    echo "Создание виртуального окружения..."
    cd backend
    python3 -m venv venv
    source venv/bin/activate
    pip install --no-cache-dir -r requirements.txt
    cd ..
fi

echo "Запуск backend в безопасном режиме..."
cd backend
source venv/bin/activate
python main.py 