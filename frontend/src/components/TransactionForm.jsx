import React, { useState } from 'react';
import {
  Paper,
  Typography,
  TextField,
  Button,
  Box,
  Alert
} from '@mui/material';
import { blockchainAPI } from '../services/blockchain';

export const TransactionForm = ({ onTransactionCreated }) => {
  const [recipient, setRecipient] = useState('');
  const [amount, setAmount] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setMessage('');
    
    try {
      const response = await blockchainAPI.createTransaction({
        recipient,
        amount: parseFloat(amount)
      });
      
      setMessage(response.data.message);
      setRecipient('');
      setAmount('');
      
      if (onTransactionCreated) {
        onTransactionCreated();
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to create transaction');
    }
  };

  return (
    <Paper elevation={3} sx={{ p: 3 }}>
      <Typography variant="h5" gutterBottom>
        Create New Transaction
      </Typography>
      
      {message && <Alert severity="success" sx={{ mb: 2 }}>{message}</Alert>}
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      
      <form onSubmit={handleSubmit}>
        <TextField
          fullWidth
          label="Recipient Address"
          value={recipient}
          onChange={(e) => setRecipient(e.target.value)}
          margin="normal"
          required
        />
        
        <TextField
          fullWidth
          label="Amount (GHC)"
          type="number"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
          margin="normal"
          required
        />
        
        <Box mt={2}>
          <Button type="submit" variant="contained" size="large">
            Send Transaction
          </Button>
        </Box>
      </form>
    </Paper>
  );
};