using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FurnitureShopProjectRazil.Models
{
    public class About
    {
        [Required]
        public int Id { get; set; }
        [Required]
        [MaxLength(50)]
        public string Title { get; set; }
        [Required]
        [MaxLength(100)]
        public string Subtitle { get; set; }

        public string ImagePath { get; set; }
        [NotMapped]
        public IFormFile Photo { get; set; }

        [Required]
        [MaxLength(200)]
        public string Icon1 { get; set; }
        [Required]
        [MaxLength(50)]
        public string Title1 { get; set; }
        [Required]
        [MaxLength(100)]
        public string Subtitle1 { get; set; }


        [Required]
        [MaxLength(200)]
        public string Icon2 { get; set; }
        [Required]
        [MaxLength(50)]
        public string Title2 { get; set; }
        [Required]
        [MaxLength(100)]
        public string Subtitle2 { get; set; }


        [Required]
        [MaxLength(200)]
        public string Icon3 { get; set; }
        [Required]
        [MaxLength(50)]
        public string Title3 { get; set; }
        [Required]
        [MaxLength(100)]
        public string Subtitle3 { get; set; }


        [Required]
        [MaxLength(200)]
        public string Icon4 { get; set; }
        [Required]
        [MaxLength(50)]
        public string Title4 { get; set; }
        [Required]
        [MaxLength(100)]
        public string Subtitle4 { get; set; }
    }
}
