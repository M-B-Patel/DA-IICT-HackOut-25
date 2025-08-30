import React, { useState } from 'react';
import {
  Paper,
  Typography,
  Button,
  Box,
  Alert,
  CircularProgress
} from '@mui/material';
import { blockchainAPI } from '../services/blockchain';

export const MiningInterface = ({ onBlockMined }) => {
  const [mining, setMining] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const handleMine = async () => {
    setMining(true);
    setError('');
    setMessage('');
    
    try {
      const response = await blockchainAPI.mineBlock();
      setMessage(response.data.message);
      
      if (onBlockMined) {
        onBlockMined();
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to mine block');
    } finally {
      setMining(false);
    }
  };

  return (
    <Paper elevation={3} sx={{ p: 3 }}>
      <Typography variant="h5" gutterBottom>
        Mining Interface
      </Typography>
      
      {message && <Alert severity="success" sx={{ mb: 2 }}>{message}</Alert>}
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      
      <Typography paragraph>
        Click the button below to mine a new block. This will process all pending transactions
        and add them to the blockchain.
      </Typography>
      
      <Box mt={2}>
        <Button 
          variant="contained" 
          size="large" 
          onClick={handleMine}
          disabled={mining}
          startIcon={mining ? <CircularProgress size={20} /> : null}
        >
          {mining ? 'Mining...' : 'Mine Block'}
        </Button>
      </Box>
    </Paper>
  );
};