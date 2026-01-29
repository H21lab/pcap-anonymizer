
import React from 'react';
import { Box, Typography, Paper, IconButton, Tooltip } from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';
import MasksIcon from '@mui/icons-material/Masks';

interface PacketDetailProps {
  packet: any;
  onAddRule: (field: string) => void;
  onAddMaskRule: (field: string) => void;
}

const DetailNode = ({ 
    label, 
    value, 
    level, 
    fullKey, 
    parentRawFields, 
    onAddRule,
    onAddMaskRule
}: { 
    label: string, 
    value: any, 
    level: number, 
    fullKey: string,
    parentRawFields: Set<string>,
    onAddRule: (field: string) => void,
    onAddMaskRule: (field: string) => void
}) => {
    const isObject = typeof value === 'object' && value !== null && !Array.isArray(value);
    
    const rawKey = label + '_raw';
    const canAnonymize = parentRawFields.has(rawKey);

    if (label.endsWith('_raw')) return null;

    return (
        <Box sx={{ ml: level * 2, borderLeft: level > 0 ? '1px solid #eee' : 'none', pl: level > 0 ? 1 : 0 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', '&:hover .anon-btn': { opacity: 1 } }}>
                <Typography variant="body2" sx={{ fontFamily: 'monospace', display: 'flex', gap: 1, py: 0.2 }}>
                    <span style={{ fontWeight: 'bold', color: '#1976d2' }}>{label}</span>
                    {(!isObject) && <span>: {String(value)}</span>}
                </Typography>
                
                {canAnonymize && (
                    <Box className="anon-btn" sx={{ display: 'flex', opacity: 0.3, transition: 'opacity 0.2s', ml: 1 }}>
                        <Tooltip title={`Anonymize ${label} (SHAKE256)`}>
                            <IconButton 
                                size="small" 
                                sx={{ py: 0 }}
                                onClick={() => onAddRule(rawKey)}
                            >
                                <SecurityIcon sx={{ fontSize: 16, color: '#ed6c02' }} />
                            </IconButton>
                        </Tooltip>
                        <Tooltip title={`Mask ${label} (0xFF)`}>
                            <IconButton 
                                size="small" 
                                sx={{ py: 0 }}
                                onClick={() => onAddMaskRule(rawKey)}
                            >
                                <MasksIcon sx={{ fontSize: 16, color: '#d32f2f' }} />
                            </IconButton>
                        </Tooltip>
                    </Box>
                )}
            </Box>
            
            {isObject && (
                <Box>
                    {Object.entries(value).map(([k, v]) => (
                        <DetailNode 
                            key={k} 
                            label={k} 
                            value={v} 
                            level={level + 1} 
                            fullKey={k}
                            parentRawFields={new Set(Object.keys(value))}
                            onAddRule={onAddRule}
                            onAddMaskRule={onAddMaskRule}
                        />
                    ))}
                </Box>
            )}
        </Box>
    );
};

export const PacketDetail: React.FC<PacketDetailProps> = ({ packet, onAddRule, onAddMaskRule }) => {
  if (!packet) return <Typography sx={{ p: 2 }}>Select a packet to view details</Typography>;
  
  const layers = packet._source?.layers || {};

  return (
    <Paper sx={{ 
        p: 2, 
        height: '100%', 
        overflow: 'auto', 
        boxSizing: 'border-box',
        display: 'flex',
        flexDirection: 'column'
    }}>
      <Typography variant="h6" gutterBottom>Packet Details</Typography>
      <Box sx={{ pb: 10 }}> {/* Added extra padding at the bottom */}
        {Object.entries(layers).map(([key, value]) => (
            <DetailNode 
                key={key} 
                label={key} 
                value={value} 
                level={0} 
                fullKey={key}
                parentRawFields={new Set(Object.keys(layers))}
                onAddRule={onAddRule}
                onAddMaskRule={onAddMaskRule}
            />
        ))}
      </Box>
    </Paper>
  );
};
