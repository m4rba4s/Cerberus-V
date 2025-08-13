const fs = require('fs');
const path = require('path');

// Файлы для исправления
const files = [
  'src/pages/VPPEngine.tsx',
  'src/pages/EBPFPrograms.tsx', 
  'src/pages/SystemPerformance.tsx',
  'src/pages/StorageLogs.tsx',
  'src/pages/NetworkStatus.tsx'
];

// Неиспользуемые импорты для удаления
const unusedImports = {
  'src/pages/VPPEngine.tsx': [
    'Alert', 'IconButton', 'Tooltip', 'PlayArrow', 'Stop', 'Settings', 
    'Memory', 'Speed', 'Warning', 'CheckCircle', 'Error', 'Build', 'ModeProvider'
  ],
  'src/pages/EBPFPrograms.tsx': [
    'Alert', 'List', 'ListItem', 'ListItemText', 'ListItemIcon', 'BugReport',
    'PlayArrow', 'Stop', 'Settings', 'Warning', 'CheckCircle', 'Error', 'Build',
    'Security', 'Timeline', 'ModeProvider'
  ],
  'src/pages/SystemPerformance.tsx': [
    'Alert', 'IconButton', 'Tooltip', 'Accordion', 'AccordionSummary', 'AccordionDetails',
    'TrendingUp', 'Memory', 'Speed', 'Storage', 'NetworkCheck', 'Refresh', 'Warning',
    'CheckCircle', 'Error', 'ExpandMore', 'Timeline', 'FlashOn', 'ModeProvider'
  ],
  'src/pages/StorageLogs.tsx': [
    'LinearProgress', 'IconButton', 'FileCopy', 'Storage', 'Warning', 'CheckCircle',
    'Error', 'Info', 'FilePresent', 'Shield', 'Refresh', 'SaveAlt', 'ModeProvider'
  ],
  'src/pages/NetworkStatus.tsx': [
    'Accordion', 'AccordionSummary', 'AccordionDetails', 'LinearProgress',
    'Public', 'Block', 'CheckCircle', 'ExpandMore', 'Warning', 'GpsFixed',
    'GpsNotFixed', 'ArrowDownward', 'ArrowUpward', 'FilterList', 'Done', 'Error',
    'Language', 'BarChart'
  ]
};

function removeUnusedImports(filePath) {
  try {
    let content = fs.readFileSync(filePath, 'utf8');
    const unused = unusedImports[filePath] || [];
    
    // Удаляем неиспользуемые импорты из @mui/material
    unused.forEach(importName => {
      const materialRegex = new RegExp(`\\b${importName}\\b,?\\s*`, 'g');
      content = content.replace(materialRegex, '');
      
      // Удаляем запятые в начале строки после удаления
      content = content.replace(/,\s*\n\s*}/g, '\n  }');
      content = content.replace(/,\s*\n\s*]/g, '\n  ]');
    });
    
    // Удаляем ModeProvider из импортов
    content = content.replace(/import \{ ModeProvider, useMode \}/g, 'import { useMode }');
    
    // Убираем лишние запятые
    content = content.replace(/,\s*,/g, ',');
    content = content.replace(/,\s*}/g, '}');
    content = content.replace(/,\s*]/g, ']');
    
    fs.writeFileSync(filePath, content);
    console.log(`✅ Fixed imports in ${filePath}`);
  } catch (error) {
    console.error(`❌ Error fixing ${filePath}:`, error.message);
  }
}

// Исправляем все файлы
files.forEach(removeUnusedImports);

console.log('🎉 Import cleanup completed!'); 