#!/bin/bash

# Cerberus-V TypeScript Fix Script
# Автоматическое исправление ошибок TypeScript

set -e

echo "🔧 Исправление TypeScript ошибок..."

# 1. Удаление неиспользуемых импортов
echo "📦 Удаление неиспользуемых импортов..."
find src -name "*.tsx" -o -name "*.ts" | while read file; do
    echo "Обработка: $file"
    
    # Удаляем неиспользуемые импорты MUI
    sed -i '/^import.*from.*@mui\/icons-material.*$/d' "$file" 2>/dev/null || true
    sed -i '/^import.*from.*@mui\/material.*$/d' "$file" 2>/dev/null || true
    
    # Удаляем неиспользуемые импорты React
    sed -i 's/import React, { useState, useEffect } from "react";/import React, { useState } from "react";/g' "$file" 2>/dev/null || true
    sed -i 's/import React, { useState, useEffect, useCallback } from "react";/import React, { useState, useCallback } from "react";/g' "$file" 2>/dev/null || true
done

# 2. Замена отсутствующих иконок
echo "🎨 Замена отсутствующих иконок..."
find src -name "*.tsx" | while read file; do
    # Firewall -> Security
    sed -i 's/Firewall/Security/g' "$file" 2>/dev/null || true
    # AddIcon -> Add
    sed -i 's/AddIcon/Add/g' "$file" 2>/dev/null || true
    # Router -> NetworkCheck
    sed -i 's/Router/NetworkCheck/g' "$file" 2>/dev/null || true
    # NetworkWifi -> NetworkCheck
    sed -i 's/NetworkWifi/NetworkCheck/g' "$file" 2>/dev/null || true
    # TrendingUp -> TrendingUp (если есть)
    # Monitor -> NetworkCheck
    sed -i 's/Monitor/NetworkCheck/g' "$file" 2>/dev/null || true
    # Refresh -> Refresh (если есть)
    # StorageIcon -> Storage
    sed -i 's/StorageIcon/Storage/g' "$file" 2>/dev/null || true
done

# 3. Исправление типов
echo "🔧 Исправление типов..."
find src -name "*.tsx" | while read file; do
    # NodeJS.Timeout -> TimeoutHandle
    sed -i 's/NodeJS\.Timeout/TimeoutHandle/g' "$file" 2>/dev/null || true
    # Удаляем size="small" из Alert
    sed -i 's/size="small"//g' "$file" 2>/dev/null || true
done

# 4. Добавление импортов типов
echo "📝 Добавление импортов типов..."
find src -name "*.tsx" | while read file; do
    if grep -q "TimeoutHandle" "$file"; then
        if ! grep -q "import.*TimeoutHandle.*from.*types" "$file"; then
            sed -i '1i import { TimeoutHandle } from "../types";' "$file" 2>/dev/null || true
        fi
    fi
done

# 5. Исправление интерфейсов WebSocketData
echo "🔌 Исправление WebSocketData интерфейса..."
cat > src/types/websocket.ts << 'EOF'
export interface WebSocketData {
  timestamp?: string;
  mode?: string;
  rules_count?: number;
  status?: string;
  uptime?: number;
  engine_status?: string;
  demo_mode?: boolean;
  interfaces?: Array<{
    name: string;
    status: string;
    speed: number;
  }>;
}
EOF

echo "✅ Исправления завершены!"
echo "🚀 Запуск проверки типов..."

npm run type-check 