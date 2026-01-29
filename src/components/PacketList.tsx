import React from 'react';
import { 
  Box, Paper
} from '@mui/material';
import { Virtuoso } from 'react-virtuoso';

interface PacketListProps {
  packets: any[];
  selectedIndex: number;
  onSelect: (index: number) => void;
}

export const PacketList: React.FC<PacketListProps> = ({ packets, selectedIndex, onSelect }) => {
  return (
    <Paper sx={{ flexGrow: 1, height: '100%', width: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <Virtuoso
        style={{ height: '100%', width: '100%' }}
        data={packets}
        components={{
          Header: () => (
            <Box sx={{ 
              display: 'flex', 
              bgcolor: '#f5f5f5', 
              fontWeight: 'bold', 
              py: 1, 
              fontSize: '0.85rem', 
              borderBottom: '2px solid #ddd',
              position: 'sticky',
              top: 0,
              zIndex: 1,
              fontFamily: 'monospace'
            }}>
              <Box sx={{ width: 60, px: 1 }}>No.</Box>
              <Box sx={{ width: 120, px: 1 }}>Time</Box>
              <Box sx={{ width: 150, px: 1 }}>Source</Box>
              <Box sx={{ width: 150, px: 1 }}>Destination</Box>
              <Box sx={{ width: 80, px: 1 }}>Protocol</Box>
              <Box sx={{ width: 60, px: 1 }}>Len</Box>
              <Box sx={{ flexGrow: 1, px: 1 }}>Info</Box>
            </Box>
          )
        }}
        itemContent={(index, packet) => {
          const layers = packet._source?.layers || {};
          const frame = layers.frame || {};
          const ip = layers.ip || layers.ipv6 || {};
          const eth = layers.eth || {};
          const summary = packet._summary;

          let no = String(index + 1);
          let time = frame['frame.time_epoch'] || '?';
          let src = ip['ip.src'] || eth['eth.src'] || '?';
          let dst = ip['ip.dst'] || eth['eth.dst'] || '?';
          let protocol = '?';
          let len = frame['frame.len'] || '?';
          let info = '';

          if (summary && Array.isArray(summary.c) && summary.c.length >= 7) {
              no = summary.c[0];
              time = summary.c[1];
              src = summary.c[2];
              dst = summary.c[3];
              protocol = summary.c[4];
              len = summary.c[5];
              info = summary.c[6];
          }

          const isSelected = index === selectedIndex;

          return (
            <Box 
              onClick={() => onSelect(index)}
              sx={{ 
                display: 'flex', 
                alignItems: 'center',
                cursor: 'pointer',
                borderBottom: '1px solid #eee',
                bgcolor: isSelected ? '#e3f2fd' : 'white',
                '&:hover': { bgcolor: isSelected ? '#bbdefb' : '#f5f5f5' },
                fontSize: '0.85rem',
                fontFamily: 'monospace',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                height: 30
              }}
            >
              <Box sx={{ width: 60, px: 1 }}>{no}</Box>
              <Box sx={{ width: 120, px: 1 }}>{typeof time === 'string' ? parseFloat(time).toFixed(4) : time}</Box>
              <Box sx={{ width: 150, px: 1, overflow: 'hidden', textOverflow: 'ellipsis' }}>{src}</Box>
              <Box sx={{ width: 150, px: 1, overflow: 'hidden', textOverflow: 'ellipsis' }}>{dst}</Box>
              <Box sx={{ width: 80, px: 1, fontWeight: 'bold' }}>{protocol}</Box>
              <Box sx={{ width: 60, px: 1 }}>{len}</Box>
              <Box sx={{ flexGrow: 1, px: 1, overflow: 'hidden', textOverflow: 'ellipsis' }}>{info}</Box>
            </Box>
          );
        }}
      />
    </Paper>
  );
};