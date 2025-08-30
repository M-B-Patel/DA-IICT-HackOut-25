import React, { useState } from 'react';
import {
  Paper,
  Typography,
  TextField,
  Button,
  Box,
  Alert,
  List,
  ListItem,
  ListItemText
} from '@mui/material';
import { blockchainAPI } from '../services/blockchain';

export const NodeManagement = () => {
  const [nodeUrl, setNodeUrl] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const handleAddNode = async (e) => {
    e.preventDefault();
    setError('');
    setMessage('');
    
    try {
      const response = await blockchainAPI.registerNodes([nodeUrl]);
      setMessage(response.data.message);
      setNodeUrl('');
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to add node');
    }
  };

  const handleResolveConflicts = async () => {
    try {
      const response = await blockchainAPI.resolveConflicts();
      setMessage(response.data.message);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to resolve conflicts');
    }
  };

  return (
    <Box>
      <Paper elevation={3} sx={{ p: 3, mb: 2 }}>
        <Typography variant="h6" gutterBottom>
          Register New Node
        </Typography>
        
        {message && <Alert severity="success" sx={{ mb: 2 }}>{message}</Alert>}
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        
        <form onSubmit={handleAddNode}>
          <TextField
            fullWidth
            label="Node URL"
            value={nodeUrl}
            onChange={(e) => setNodeUrl(e.target.value)}
            margin="normal"
            required
            placeholder="http://localhost:5001"
          />
          
          <Box mt={2}>
            <Button type="submit" variant="contained">
              Add Node
            </Button>
          </Box>
        </form>
      </Paper>

      <Paper elevation={3} sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom>
          Consensus
        </Typography>
        
        <Button variant="contained" onClick={handleResolveConflicts}>
          Resolve Conflicts
        </Button>
      </Paper>
    </Box>
  );
};