#!/bin/bash

# Cerberus-V Static Analysis Script
# Комплексный анализ кода для обеспечения качества

set -e

echo "🔍 Запуск статического анализа Cerberus-V..."

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Счетчики
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

# Функция для проверки
check() {
    local name="$1"
    local command="$2"
    
    echo -e "${BLUE}🔍 Проверка: $name${NC}"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if eval "$command"; then
        echo -e "${GREEN}✅ $name: ПРОЙДЕН${NC}"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        echo -e "${RED}❌ $name: ПРОВАЛЕН${NC}"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
    echo ""
}

# 1. Проверка типов TypeScript
check "TypeScript Type Check" "npm run type-check"

# 2. ESLint проверка
check "ESLint Linting" "npm run lint"

# 3. Prettier форматирование
check "Prettier Format Check" "npm run format:check"

# 4. Аудит безопасности
check "Security Audit" "npm run security:audit"

# 5. Проверка зависимостей
check "Dependency Check" "npm ls --depth=0"

# 6. Проверка размера бандла
check "Bundle Size Check" "npm run build"

# 7. Проверка тестов (если есть)
if [ -f "vitest.config.ts" ] || [ -f "jest.config.js" ]; then
    check "Unit Tests" "npm run test"
fi

# Итоговый отчет
echo "📊 ИТОГОВЫЙ ОТЧЕТ"
echo "=================="
echo -e "${BLUE}Всего проверок: $TOTAL_CHECKS${NC}"
echo -e "${GREEN}Пройдено: $PASSED_CHECKS${NC}"
echo -e "${RED}Провалено: $FAILED_CHECKS${NC}"

if [ $FAILED_CHECKS -eq 0 ]; then
    echo -e "${GREEN}🎉 Все проверки пройдены успешно!${NC}"
    exit 0
else
    echo -e "${RED}⚠️  Обнаружены проблемы. Требуется исправление.${NC}"
    exit 1
fi 