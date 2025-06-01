using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace FurnitureShopProjectRazil.Models
{
    public class Cart
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public int UserId { get; set; } // User modelinizin Id tipi ilə eyni olmalıdır
        public virtual User User { get; set; }

        public DateTime CreatedDate { get; set; } = DateTime.UtcNow;
        public DateTime? LastModifiedDate { get; set; }

        public virtual ICollection<CartItem> Items { get; set; } = new List<CartItem>();
    }
}