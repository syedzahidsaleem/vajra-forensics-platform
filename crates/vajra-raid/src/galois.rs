//! Galois Field GF(2^8) arithmetic for RAID 6 Reed-Solomon dual-parity reconstruction (§15 Part III).
//!
//! Implements the canonical Linux software RAID 6 polynomial (0x11D = x^8 + x^4 + x^3 + x^2 + 1)
//! with O(1) exponent and logarithm tables for on-the-fly degraded reconstruction.

pub const GF_POLY: u16 = 0x11d;

pub struct GaloisField {
    exp_table: [u8; 512],
    log_table: [u8; 256],
    inv_table: [u8; 256],
}

impl GaloisField {
    pub fn new() -> Self {
        let mut exp_table = [0u8; 512];
        let mut log_table = [0u8; 256];
        let mut inv_table = [0u8; 256];

        let mut val = 1u16;
        for i in 0..255 {
            exp_table[i] = val as u8;
            exp_table[i + 255] = val as u8;
            log_table[val as usize] = i as u8;

            val <<= 1;
            if (val & 0x100) != 0 {
                val ^= GF_POLY;
            }
        }
        exp_table[510] = exp_table[0];
        exp_table[511] = exp_table[1];

        inv_table[0] = 0;
        for i in 1..=255 {
            let log_i = log_table[i] as usize;
            let inv_log = (255 - log_i) % 255;
            inv_table[i] = exp_table[inv_log];
        }

        Self {
            exp_table,
            log_table,
            inv_table,
        }
    }

    #[inline(always)]
    pub fn add(&self, a: u8, b: u8) -> u8 {
        a ^ b
    }

    #[inline(always)]
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            let log_a = self.log_table[a as usize] as usize;
            let log_b = self.log_table[b as usize] as usize;
            self.exp_table[log_a + log_b]
        }
    }

    #[inline(always)]
    pub fn div(&self, a: u8, b: u8) -> u8 {
        if a == 0 {
            0
        } else if b == 0 {
            panic!("Division by zero in GF(2^8)");
        } else {
            let log_a = self.log_table[a as usize] as usize;
            let log_b = self.log_table[b as usize] as usize;
            self.exp_table[log_a + 255 - log_b]
        }
    }

    #[inline(always)]
    pub fn inv(&self, a: u8) -> u8 {
        self.inv_table[a as usize]
    }

    #[inline(always)]
    pub fn g_pow(&self, power: usize) -> u8 {
        self.exp_table[power % 255]
    }

    /// Computes P parity: P = D_0 ^ D_1 ^ ... ^ D_{k-1}
    pub fn compute_p_parity(&self, data_blocks: &[&[u8]], out_p: &mut [u8]) {
        out_p.fill(0);
        for block in data_blocks {
            for (p_byte, &d_byte) in out_p.iter_mut().zip(block.iter()) {
                *p_byte ^= d_byte;
            }
        }
    }

    /// Computes Q parity: Q = g^0*D_0 ^ g^1*D_1 ^ ... ^ g^{k-1}*D_{k-1} where g=2
    pub fn compute_q_parity(&self, data_blocks: &[&[u8]], out_q: &mut [u8]) {
        out_q.fill(0);
        for (i, block) in data_blocks.iter().enumerate() {
            let coeff = self.g_pow(i);
            for (q_byte, &d_byte) in out_q.iter_mut().zip(block.iter()) {
                *q_byte ^= self.mul(coeff, d_byte);
            }
        }
    }

    /// Reconstructs single missing data drive when P parity is present.
    /// D_x = P ^ sum_{i != x} D_i
    pub fn reconstruct_with_p(
        &self,
        intact_data: &[(usize, &[u8])],
        p_block: &[u8],
        out_missing: &mut [u8],
    ) {
        out_missing.copy_from_slice(p_block);
        for (_, block) in intact_data {
            for (m_byte, &d_byte) in out_missing.iter_mut().zip(block.iter()) {
                *m_byte ^= d_byte;
            }
        }
    }

    /// Reconstructs single missing data drive when Q parity is present (and P is missing).
    /// D_x = g^{-x} * (Q ^ sum_{i != x} g^i * D_i)
    pub fn reconstruct_with_q(
        &self,
        intact_data: &[(usize, &[u8])],
        q_block: &[u8],
        missing_idx: usize,
        out_missing: &mut [u8],
    ) {
        let mut q_sum = vec![0u8; q_block.len()];
        q_sum.copy_from_slice(q_block);

        for &(i, block) in intact_data {
            let coeff = self.g_pow(i);
            for (q_byte, &d_byte) in q_sum.iter_mut().zip(block.iter()) {
                *q_byte ^= self.mul(coeff, d_byte);
            }
        }

        let inv_gx = self.inv(self.g_pow(missing_idx));
        for (m_byte, &q_byte) in out_missing.iter_mut().zip(q_sum.iter()) {
            *m_byte = self.mul(inv_gx, q_byte);
        }
    }

    /// Reconstructs two missing data drives (D_x, D_y with x < y) using both P and Q parities.
    /// P_xy = P ^ sum_{i != x, y} D_i = D_x ^ D_y
    /// Q_xy = Q ^ sum_{i != x, y} g^i * D_i = g^x * D_x ^ g^y * D_y
    /// D_y = (Q_xy ^ g^x * P_xy) / (g^y ^ g^x)
    /// D_x = P_xy ^ D_y
    pub fn reconstruct_2_data(
        &self,
        intact_data: &[(usize, &[u8])],
        p_block: &[u8],
        q_block: &[u8],
        idx_x: usize,
        idx_y: usize,
        out_x: &mut [u8],
        out_y: &mut [u8],
    ) {
        let mut p_xy = vec![0u8; p_block.len()];
        p_xy.copy_from_slice(p_block);
        for (_, block) in intact_data {
            for (p_b, &d_b) in p_xy.iter_mut().zip(block.iter()) {
                *p_b ^= d_b;
            }
        }

        let mut q_xy = vec![0u8; q_block.len()];
        q_xy.copy_from_slice(q_block);
        for &(i, block) in intact_data {
            let coeff = self.g_pow(i);
            for (q_b, &d_b) in q_xy.iter_mut().zip(block.iter()) {
                *q_b ^= self.mul(coeff, d_b);
            }
        }

        let gx = self.g_pow(idx_x);
        let gy = self.g_pow(idx_y);
        let denom_inv = self.inv(self.add(gy, gx));

        for (i, d_y_byte) in out_y.iter_mut().enumerate() {
            let p_val = p_xy[i];
            let q_val = q_xy[i];
            let num = self.add(q_val, self.mul(gx, p_val));
            let dy = self.mul(num, denom_inv);
            *d_y_byte = dy;
            out_x[i] = self.add(p_val, dy);
        }
    }
}

impl Default for GaloisField {
    fn default() -> Self {
        Self::new()
    }
}
