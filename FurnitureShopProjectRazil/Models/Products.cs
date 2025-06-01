using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Http; // IFormFile üçün

namespace FurnitureShopProjectRazil.Models
{
    public class Products
    {
        [Key]
        public int Id { get; set; }
        public string? ImagePath { get; set; } // Nullable etdim

        [NotMapped]
        public IFormFile? Photo { get; set; } // Nullable etdim

        [Required]
        [StringLength(100, ErrorMessage = "Başlıq maksimum 100 simvol olmalıdır.")]
        public string Title { get; set; }

        [Required]
        [Column(TypeName = "decimal(18,2)")] // Verilənlər bazasında düzgün tip üçün
        public decimal Price { get; set; } // STRING YERİNƏ DECIMAL
    }
}