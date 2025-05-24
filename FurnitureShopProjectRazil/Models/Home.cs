using System.ComponentModel.DataAnnotations;

namespace FurnitureShopProjectRazil.Models
{
    public class Home
    {
        [Required]
        public int Id { get; set; }
        [Required]
        [MaxLength(50)]
        public string Title { get; set; }
        [Required]
        [MaxLength(100)]
        public string Subtitle { get; set; }
    }
}
