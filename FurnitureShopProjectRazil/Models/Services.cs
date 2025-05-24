using System.ComponentModel.DataAnnotations;

namespace FurnitureShopProjectRazil.Models
{
    public class Services
    {
        [Required]
        public int Id { get; set; }
        [Required]
        [MaxLength(200)]
        public string Icon { get; set; }
        [Required]
        [MaxLength(50)]
        public string Title { get; set; }
        [Required]
        [MaxLength(100)]
        public string Subtitle { get; set; }
    }
}
