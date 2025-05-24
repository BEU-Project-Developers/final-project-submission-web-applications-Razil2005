namespace FurnitureShopProjectRazil.Models
{
    public class Testimonial
    {
        public int Id { get; set; }
        public string Note { get; set; }
        public string ImagePath { get; set; }
        public IFormFile Photo { get; set; }
        public int UserId { get; set; }
        public User User { get; set; }
    }
}
