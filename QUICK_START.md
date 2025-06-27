# 🛡️ Cerberus-V - Быстрый запуск

## Одной командой запустить ВСЁ:

```bash
./start-cerberus.sh
```

## Только фаервол (быстро):

```bash
./start-firewall.sh
```

## Что запускается:

### 🛡️ Фаервол (всегда)
- **Control Plane** на порту `50051`
- **eBPF + VPP** обработка пакетов
- **API endpoints** для управления

### 📊 Мониторинг (полная версия)
- **Prometheus** на порту `9090` 
- **Grafana** на порту `3005` (admin/monitoring123)

### 🎨 GUI (полная версия)
- **Backend** на порту `8000-8004` (автоматически)
- **Frontend** на порту `5173-5175` (автоматически)

## Проверка работы:

```bash
# Проверить фаервол
curl http://localhost:50051/health

# Статистика пакетов  
curl http://localhost:50051/stats

# Правила фаервола
curl http://localhost:50051/rules
```

## Веб интерфейсы:

- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3005
- **GUI**: http://localhost:5173 (или другой порт)

## Остановка:

Нажми `Ctrl+C` в терминале или:

```bash
pkill -f 'cerberus|go run'
```

## Логи:

- `control.log` - фаервол
- `gui-backend.log` - GUI backend  
- `gui-frontend.log` - GUI frontend

## Тесты:

```bash
cd tests/integration
python3 demo_tests.py
```

## Системные требования:

- Go 1.19+
- Python 3.8+
- Node.js 16+
- Docker & Docker Compose
- Linux с поддержкой eBPF

## Поддержка:

Если что-то не работает:
1. Проверь логи в файлах `*.log`
2. Убей процессы: `pkill -f cerberus`
3. Перезапусти: `./start-cerberus.sh` 