using System.Collections.Generic; // ICollection üçün
using System.ComponentModel.DataAnnotations; // Data Annotations üçün

namespace FurnitureShopProjectRazil.Models
{
    public class Profession
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(100)] // Məntiqli bir uzunluq təyin edin
        public string Name { get; set; }

        // Bir peşə bir çox komanda üzvünə aid ola bilər
        public ICollection<Team> Teams { get; set; } = new List<Team>();
    }
}