#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Функция для очистки импортов в файле
function cleanImports(filePath) {
    let content = fs.readFileSync(filePath, 'utf8');
    let modified = false;

    // Удаляем неиспользуемые импорты из @mui/icons-material
    const iconImports = content.match(/import\s*{([^}]+)}\s*from\s*['"]@mui\/icons-material['"];?/g);
    if (iconImports) {
        iconImports.forEach(importStr => {
            const matches = importStr.match(/import\s*{([^}]+)}\s*from\s*['"]@mui\/icons-material['"];?/);
            if (matches) {
                const icons = matches[1].split(',').map(i => i.trim());
                const usedIcons = icons.filter(icon => {
                    const iconName = icon.split(' as ')[0].trim();
                    return content.includes(iconName) && !iconName.includes('Icon');
                });
                
                if (usedIcons.length === 0) {
                    content = content.replace(importStr, '');
                    modified = true;
                } else if (usedIcons.length !== icons.length) {
                    const newImport = `import { ${usedIcons.join(', ')} } from '@mui/icons-material';`;
                    content = content.replace(importStr, newImport);
                    modified = true;
                }
            }
        });
    }

    // Удаляем неиспользуемые импорты из @mui/material
    const materialImports = content.match(/import\s*{([^}]+)}\s*from\s*['"]@mui\/material['"];?/g);
    if (materialImports) {
        materialImports.forEach(importStr => {
            const matches = importStr.match(/import\s*{([^}]+)}\s*from\s*['"]@mui\/material['"];?/);
            if (matches) {
                const components = matches[1].split(',').map(c => c.trim());
                const usedComponents = components.filter(comp => {
                    const compName = comp.split(' as ')[0].trim();
                    return content.includes(compName);
                });
                
                if (usedComponents.length === 0) {
                    content = content.replace(importStr, '');
                    modified = true;
                } else if (usedComponents.length !== components.length) {
                    const newImport = `import { ${usedComponents.join(', ')} } from '@mui/material';`;
                    content = content.replace(importStr, newImport);
                    modified = true;
                }
            }
        });
    }

    // Удаляем неиспользуемые React импорты
    const reactImports = content.match(/import\s*React,\s*{([^}]+)}\s*from\s*['"]react['"];?/g);
    if (reactImports) {
        reactImports.forEach(importStr => {
            const matches = importStr.match(/import\s*React,\s*{([^}]+)}\s*from\s*['"]react['"];?/);
            if (matches) {
                const hooks = matches[1].split(',').map(h => h.trim());
                const usedHooks = hooks.filter(hook => {
                    return content.includes(hook);
                });
                
                if (usedHooks.length === 0) {
                    content = content.replace(importStr, 'import React from "react";');
                    modified = true;
                } else if (usedHooks.length !== hooks.length) {
                    const newImport = `import React, { ${usedHooks.join(', ')} } from "react";`;
                    content = content.replace(importStr, newImport);
                    modified = true;
                }
            }
        });
    }

    // Заменяем отсутствующие иконки
    const iconReplacements = {
        'Firewall': 'Security',
        'AddIcon': 'Add',
        'Router': 'NetworkCheck',
        'NetworkWifi': 'NetworkCheck',
        'Monitor': 'NetworkCheck',
        'StorageIcon': 'Storage',
        'SecurityIcon': 'Security',
        'WarningIcon': 'Warning',
        'ErrorIcon': 'Error',
        'InfoIcon': 'Info',
        'CheckCircleIcon': 'CheckCircle',
        'ExpandMoreIcon': 'ExpandMore',
        'SettingsIcon': 'Settings',
        'NetworkCheckIcon': 'NetworkCheck',
        'LockIcon': 'Lock',
        'FingerprintIcon': 'Fingerprint',
        'SpeedIcon': 'Speed',
        'StopIcon': 'Stop',
        'RestartAltIcon': 'RestartAlt',
        'PlayArrowIcon': 'PlayArrow'
    };

    Object.entries(iconReplacements).forEach(([oldIcon, newIcon]) => {
        if (content.includes(oldIcon)) {
            content = content.replace(new RegExp(oldIcon, 'g'), newIcon);
            modified = true;
        }
    });

    // Удаляем size="small" из Alert компонентов
    content = content.replace(/size="small"/g, '');
    modified = true;

    // Заменяем NodeJS.Timeout на TimeoutHandle
    if (content.includes('NodeJS.Timeout')) {
        content = content.replace(/NodeJS\.Timeout/g, 'TimeoutHandle');
        modified = true;
    }

    if (modified) {
        fs.writeFileSync(filePath, content);
        console.log(`✅ Очищен: ${filePath}`);
    }
}

// Рекурсивно находим все .tsx и .ts файлы
function findFiles(dir) {
    const files = [];
    const items = fs.readdirSync(dir);
    
    items.forEach(item => {
        const fullPath = path.join(dir, item);
        const stat = fs.statSync(fullPath);
        
        if (stat.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
            files.push(...findFiles(fullPath));
        } else if (item.endsWith('.tsx') || item.endsWith('.ts')) {
            files.push(fullPath);
        }
    });
    
    return files;
}

// Основная функция
function main() {
    console.log('🧹 Очистка неиспользуемых импортов...');
    
    const srcDir = path.join(__dirname, '..', 'src');
    const files = findFiles(srcDir);
    
    files.forEach(file => {
        try {
            cleanImports(file);
        } catch (error) {
            console.error(`❌ Ошибка при обработке ${file}:`, error.message);
        }
    });
    
    console.log('✅ Очистка завершена!');
}

main(); 