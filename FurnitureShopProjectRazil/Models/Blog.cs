using System;

namespace FurnitureShopProjectRazil.Models
{
    public class Blog
    {
        public int Id { get; set; }
        public string ImagePath { get; set; }
        public IFormFile Photo { get; set; }

        public string PersonalNote { get; set; }
        public DateTime Date { get; set; }

        
    }

}
