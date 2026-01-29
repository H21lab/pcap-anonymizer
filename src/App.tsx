
import React, { useState, useCallback, memo } from 'react';
import { 
  AppBar, Toolbar, Typography, Paper, Box, Button, 
  TextField, List, ListItem, ListItemText, 
  CircularProgress, IconButton, Snackbar, Alert, InputBase, Divider
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import DownloadIcon from '@mui/icons-material/Download';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import FilterListIcon from '@mui/icons-material/FilterList';
import ClearIcon from '@mui/icons-material/Clear';
import { Panel, Group as PanelGroup, Separator as PanelResizeHandle } from "react-resizable-panels";
import { WasmDissector } from './core/dissector';
import { PacketList } from './components/PacketList';
import { PacketDetail } from './components/PacketDetail';
import { APP_VERSION } from './version';

const dissector = new WasmDissector();
const MemoizedPacketList = memo(PacketList);
const MemoizedPacketDetail = memo(PacketDetail);

function App() {
  const [packets, setPackets] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [fileLoaded, setFileLoaded] = useState(false);
  const [maskFields, setMaskFields] = useState<string[]>([]);
  const [anonymizeFields, setAnonymizeFields] = useState<string[]>(['ip.src_raw', 'ip.dst_raw']);
  const [newField, setNewField] = useState('');
  const [salt, setSalt] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [selectedPacketIndex, setSelectedPacketIndex] = useState<number>(0);
  
  const [filterInput, setFilterInput] = useState('');
  const [filterStatus, setFilterStatus] = useState<'idle' | 'valid' | 'invalid'>('idle');

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file) processFile(file);
  }, []);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) processFile(e.target.files[0]);
  };

  const processFile = async (file: File, filter: string = "") => {
    setLoading(true);
    setFileLoaded(false);
    try {
      const data = await dissector.dissect(file, filter);
      setPackets(data);
      setSelectedPacketIndex(0);
      setFilterStatus(filter ? 'valid' : 'idle');
      setFileLoaded(true);
    } catch (err) {
      setError("Failed to parse file: " + err);
    } finally {
      setLoading(false);
    }
  };

  const handleApplyFilter = async () => {
      setLoading(true);
      try {
          const data = await dissector.reDissect(filterInput);
          setPackets(data);
          setSelectedPacketIndex(0);
          setFilterStatus(filterInput ? 'valid' : 'idle');
      } catch (err) {
          setFilterStatus('invalid');
          setError("Filter error: " + err);
      } finally {
          setLoading(false);
      }
  };

  const handleClearFilter = () => {
      setFilterInput('');
      handleApplyFilter();
  };

  const handleAddField = (type: 'mask' | 'anonymize') => {
    if (!newField) return;
    if (type === 'mask') {
      if (!maskFields.includes(newField)) setMaskFields([...maskFields, newField]);
    } else {
      if (!anonymizeFields.includes(newField)) setAnonymizeFields([...anonymizeFields, newField]);
    }
    setNewField('');
  };

  const handleAddRule = useCallback((field: string) => {
    setAnonymizeFields(prev => !prev.includes(field) ? [...prev, field] : prev);
  }, []);

  const handleAddMaskRule = useCallback((field: string) => {
    setMaskFields(prev => !prev.includes(field) ? [...prev, field] : prev);
  }, []);

  const handleRemoveField = (type: 'mask' | 'anonymize', index: number) => {
    if (type === 'mask') setMaskFields(maskFields.filter((_, i) => i !== index));
    else setAnonymizeFields(anonymizeFields.filter((_, i) => i !== index));
  };

  const handleProcessAndDownload = async () => {
    if (packets.length === 0) return;
    setLoading(true);
    const worker = new Worker(new URL('./core/packet.worker.ts', import.meta.url));
    worker.onmessage = (e) => {
      const { type, blob, error } = e.data;
      setLoading(false);
      if (type === 'success') {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filterInput ? 'filtered_anonymized.pcap' : 'anonymized.pcap';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      } else setError("Processing failed: " + error);
      worker.terminate();
    };
    worker.postMessage({ packets, config: { mask: maskFields, anonymize: anonymizeFields, salt: salt || undefined }});
  };

  return (
    <Box sx={{ height: '100vh', display: 'flex', flexDirection: 'column', bgcolor: '#f5f5f5', overflow: 'hidden' }}>
      <AppBar position="static" sx={{ flexShrink: 0 }}>
        <Toolbar><Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>PCAP Anonymizer</Typography></Toolbar>
      </AppBar>

      <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', p: 2 }}>
        {fileLoaded && (
            <Paper component="form" onSubmit={(e) => { e.preventDefault(); handleApplyFilter(); }} sx={{ p: '2px 4px', display: 'flex', alignItems: 'center', mb: 2, bgcolor: filterStatus === 'invalid' ? '#ffebee' : (filterStatus === 'valid' ? '#e8f5e9' : 'white') }}>
                <FilterListIcon sx={{ p: '10px' }} />
                <InputBase sx={{ ml: 1, flex: 1, fontFamily: 'monospace' }} placeholder="Wireshark filter..." value={filterInput} onChange={(e) => setFilterInput(e.target.value)} />
                {filterInput && <IconButton size="small" onClick={handleClearFilter}><ClearIcon fontSize="small" /></IconButton>}
                <Divider sx={{ height: 28, m: 0.5 }} orientation="vertical" />
                <Button size="small" variant="contained" onClick={handleApplyFilter} disabled={loading} sx={{ mx: 1 }}>Apply</Button>
            </Paper>
        )}

        {!fileLoaded && !loading && (
          <Paper sx={{ p: 6, textAlign: 'center', cursor: 'pointer', border: '2px dashed #ccc', '&:hover': { bgcolor: '#f0f0f0' }, flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center' }} onDrop={handleDrop} onDragOver={e => e.preventDefault()} onClick={() => document.getElementById('file-input')?.click()}>
            <input id="file-input" type="file" style={{ display: 'none' }} onChange={handleFileSelect} />
            <CloudUploadIcon sx={{ fontSize: 60, color: '#aaa', mb: 2 }} />
            <Typography variant="h5" color="textSecondary">Drag & Drop PCAP file here or Click to Browse</Typography>
            <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
                (All processing happens locally in your browser memory)
            </Typography>
          </Paper>
        )}

        {loading && !fileLoaded && <Box sx={{ flex: 1, display: 'flex', justifyContent: 'center', alignItems: 'center' }}><CircularProgress /></Box>}

        {fileLoaded && (
          <Box sx={{ flex: 1, minHeight: 0 }}>
            <PanelGroup orientation="horizontal" id="main-layout" style={{ height: '100%' }}>
              <Panel defaultSize={25} minSize={20}>
                <Paper sx={{ p: 2, height: '100%', overflowY: 'auto' }}>
                  <Typography variant="h6" gutterBottom>Anonymization Rules</Typography>
                  <TextField label="Field Name" variant="outlined" size="small" fullWidth value={newField} onChange={e => setNewField(e.target.value)} sx={{ mb: 1 }} />
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <Button variant="contained" size="small" onClick={() => handleAddField('anonymize')}>Add Anonymize</Button>
                    <Button variant="outlined" size="small" onClick={() => handleAddField('mask')}>Add Mask</Button>
                  </Box>
                  <Typography variant="subtitle2" sx={{ mt: 2, color: '#ed6c02', fontWeight: 'bold' }}>Anonymize (SHAKE256):</Typography>
                  <List dense>{anonymizeFields.map((f, i) => <ListItem key={i} secondaryAction={<IconButton size="small" onClick={() => handleRemoveField('anonymize', i)}><DeleteIcon fontSize="small" /></IconButton>}><ListItemText primaryTypographyProps={{ fontSize: '0.8rem' }} primary={f} /></ListItem>)}</List>
                  <Typography variant="subtitle2" sx={{ mt: 1, color: '#d32f2f', fontWeight: 'bold' }}>Mask (0xFF):</Typography>
                  <List dense>{maskFields.map((f, i) => <ListItem key={i} secondaryAction={<IconButton size="small" onClick={() => handleRemoveField('mask', i)}><DeleteIcon fontSize="small" /></IconButton>}><ListItemText primaryTypographyProps={{ fontSize: '0.8rem' }} primary={f} /></ListItem>)}</List>
                  <TextField label="Salt (Optional)" variant="outlined" size="small" fullWidth value={salt} onChange={e => setSalt(e.target.value)} sx={{ mt: 2, mb: 2 }} />
                  <Button variant="contained" color="primary" fullWidth startIcon={loading ? <CircularProgress size={20} /> : <DownloadIcon />} onClick={handleProcessAndDownload} disabled={loading}>Download Anonymized PCAP</Button>
                  <Button sx={{ mt: 1 }} size="small" fullWidth color="secondary" onClick={() => { setPackets([]); setFileLoaded(false); setFilterInput(''); }}>Reset / Load New File</Button>
                </Paper>
              </Panel>
              <PanelResizeHandle style={{ width: '8px', cursor: 'col-resize', backgroundColor: '#ddd', margin: '0 4px', borderRadius: '4px', border: '1px solid #ccc' }} />
              <Panel defaultSize={75}>
                <PanelGroup orientation="vertical" id="preview-layout" style={{ height: '100%' }}>
                  <Panel defaultSize={50} minSize={20}>
                    <MemoizedPacketList packets={packets} selectedIndex={selectedPacketIndex} onSelect={setSelectedPacketIndex} />
                  </Panel>
                  <PanelResizeHandle style={{ height: '8px', cursor: 'row-resize', backgroundColor: '#ddd', margin: '4px 0', borderRadius: '4px', border: '1px solid #ccc' }} />
                  <Panel defaultSize={50} minSize={20}>
                    <Box sx={{ height: '100%', overflow: 'hidden' }}>
                       {packets[selectedPacketIndex] && <MemoizedPacketDetail packet={packets[selectedPacketIndex]} onAddRule={handleAddRule} onAddMaskRule={handleAddMaskRule} />}
                    </Box>
                  </Panel>
                </PanelGroup>
              </Panel>
            </PanelGroup>
          </Box>
        )}
      </Box>

      {/* Footer Disclaimer and Privacy */}
      <Box sx={{ p: 1.5, bgcolor: '#f5f5f5', borderTop: '1px solid #ddd', textAlign: 'center', flexShrink: 0 }}>
        <Typography variant="caption" color="textSecondary" component="div">
          <strong>PCAP Anonymizer v{APP_VERSION}</strong> | <strong>Privacy:</strong> This application is entirely client-based. Your PCAP files are processed locally in your browser memory and are never uploaded to any server. | <strong>Disclaimer:</strong> This software is provided "as is" without warranty of any kind. The anonymization logic may not be exhaustive for all protocols. Please review your exported PCAPs carefully before sharing or using them in sensitive environments. Source code is available under GNU GPLv2 at <a href="https://github.com/H21lab/pcap-anonymizer" target="_blank" rel="noopener noreferrer" style={{ color: 'inherit' }}>https://github.com/H21lab/pcap-anonymizer</a>. | Copyright H21 lab.
        </Typography>
      </Box>
      
      <Snackbar open={!!error} autoHideDuration={6000} onClose={() => setError(null)}><Alert severity="error">{error}</Alert></Snackbar>
    </Box>
  );
}

export default App;
