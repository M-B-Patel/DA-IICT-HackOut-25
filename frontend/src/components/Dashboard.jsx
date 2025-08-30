import React from 'react';
import {
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  Box
} from '@mui/material';

export const Dashboard = ({ blockchain, onRefresh }) => {
  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
        <Typography variant="h4">Blockchain Overview</Typography>
        <Button variant="contained" onClick={onRefresh}>
          Refresh Data
        </Button>
      </Box>
      
      <Typography variant="h6" gutterBottom>
        Chain Length: {blockchain.length}
      </Typography>
      
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Index</TableCell>
              <TableCell>Timestamp</TableCell>
              <TableCell>Transactions</TableCell>
              <TableCell>Previous Hash</TableCell>
              <TableCell>Hash</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {blockchain.chain.map((block) => (
              <TableRow key={block.index}>
                <TableCell>{block.index}</TableCell>
                <TableCell>
                  {new Date(block.timestamp * 1000).toLocaleString()}
                </TableCell>
                <TableCell>{block.transactions.length}</TableCell>
                <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.7rem' }}>
                  {block.previous_hash.substring(0, 20)}...
                </TableCell>
                <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.7rem' }}>
                  {block.hash.substring(0, 20)}...
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};