using System.ComponentModel.DataAnnotations;

namespace FurnitureShopProjectRazil.Models
{
    public class Products
    {
        [Required]
        public int Id { get; set; }
        public string ImagePath { get; set; }
        public IFormFile Photo { get; set; }
        [Required]
        [MaxLength(50)]
        public string Title { get; set; }
        [Required]
        public string Price { get; set; }
    }
}
