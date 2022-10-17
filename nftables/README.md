## 1. CVE-2022-1015

From: http://blog.dbouman.nl/2022/04/02/How-The-Tables-Have-Turned-CVE-2022-1015-1016

Root cause: length can be controled by user, which is checked improperly. As a result, length can be minus. The length is validated later, however, there exists a integer-overflow bug in the checking function.

[linux-kernel-vulnerabilities-root-cause-analysis](https://github.com/now4yreal/linux-kernel-vulnerabilities-root-cause-analysis)

Related code:

```



int nft_parse_register_load(const struct nlattr *attr, u8 *sreg, u32 len)
{
  
    /* Given a netlink attribute and the length
     * that is required to read the requested data,
     * write a register index to `sreg` or return
     * an error on failure. */
  
    u32 reg;
    int err;
  
  
    reg = nft_parse_register(attr);
    err = nft_validate_register_load(reg, len);
    if (err < 0)
        return err;
  
    /* Write resulting index to the nft_expr.data structure. */
    *sreg = reg;
    return 0;
}

-----
  
static unsigned int nft_parse_register(const struct nlattr *attr)
{
    /* Convert a register to an index in nft_regs */
  
    unsigned int reg;
  
    /* Get specified register from netlink attribute */
    reg = ntohl(nla_get_be32(attr));
  
    switch (reg) {
    /* If it's 0 to 4 inclusive, 
     * it's an OG 16-byte register and we need to 
     * multiply the index by 4 (4*4=16) */
    case NFT_REG_VERDICT...NFT_REG_4:
        return reg * NFT_REG_SIZE / NFT_REG32_SIZE;
  
    /* Else we subtract 4, since we need to account
     * for the OG registers above. */
    default:
        return reg + NFT_REG_SIZE / NFT_REG32_SIZE - NFT_REG32_00;
    }

    /* So supplied values of 1, 2, 3, 4 map to 
     * OG 16-byte registers, with indices 4, 8,
     * 12, 16
     * Supplied values of 5, 6, 7 overlap the verdict,
     * 8,9,10,11   overlap with OG register 1
     * 12,13,14,15 overlap with OG register 2
     * etc. */

}

-----

static int nft_validate_register_load(enum nft_registers reg, unsigned int len)
{
    /* We can never read from the verdict register,
     * so bail out if the index is 0,1,2,3 */
    if (reg < NFT_REG_1 * NFT_REG_SIZE / NFT_REG32_SIZE)
        return -EINVAL;
  
    /* Invalid operation, bail out */
    if (len == 0)
        return -EINVAL;
  
    /* If there would be an OOB access whenever
     * `reg` is taken as index and `len` bytes are read,
     * bail out. 
     * sizeof_field(struct nft_regs, data) == 0x50 */
    if (reg * NFT_REG32_SIZE + len > sizeof_field(struct nft_regs, data)) 
        return -ERANGE;

    return 0;
}  

```
